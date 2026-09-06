package validation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rossoctl/cortex/authbridge/authlib/redact"
)

// JWKSVerifier validates JWTs using a JWKS endpoint with auto-refreshing key cache.
type JWKSVerifier struct {
	jwksURL        string
	issuer         string
	cache          *jwk.Cache
	debugLogClaims bool
}

// JWKSOption configures JWKSVerifier behavior.
type JWKSOption func(*jwksConfig)

type jwksConfig struct {
	refreshInterval time.Duration
	debugLogClaims  bool
}

// WithRefreshInterval sets the JWKS cache refresh interval.
func WithRefreshInterval(d time.Duration) JWKSOption {
	return func(c *jwksConfig) { c.refreshInterval = d }
}

// WithDebugLogClaims enables Debug-level logging of every token's full
// decoded claim set (registered + private) on every Verify call, success or
// failure-by-audience-mismatch. Dev / incident-response only — the logged
// claims are PII (email, name, preferred_username, etc.); never enable on a
// shared or production cluster. Off by default.
func WithDebugLogClaims(enabled bool) JWKSOption {
	return func(c *jwksConfig) { c.debugLogClaims = enabled }
}

// NewJWKSVerifier creates a Verifier that validates JWTs against a JWKS endpoint.
// The JWKS keys are cached and auto-refreshed in the background.
func NewJWKSVerifier(ctx context.Context, jwksURL, issuer string, opts ...JWKSOption) (*JWKSVerifier, error) {
	cfg := &jwksConfig{
		refreshInterval: 15 * time.Minute,
	}
	for _, o := range opts {
		o(cfg)
	}

	cache := jwk.NewCache(ctx)
	regOpts := []jwk.RegisterOption{
		jwk.WithMinRefreshInterval(cfg.refreshInterval),
	}
	if err := cache.Register(jwksURL, regOpts...); err != nil {
		return nil, fmt.Errorf("registering JWKS URL %s: %w", jwksURL, err)
	}

	return &JWKSVerifier{
		jwksURL:        jwksURL,
		issuer:         issuer,
		cache:          cache,
		debugLogClaims: cfg.debugLogClaims,
	}, nil
}

// Verify parses and validates a JWT token against the cached JWKS.
// Checks signature, expiration, issuer, and audience.
// The token is accepted if its aud claim contains any of the expected audiences.
func (v *JWKSVerifier) Verify(ctx context.Context, tokenStr string, audiences []string) (*Claims, error) {
	keySet, err := v.cache.Get(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	if len(audiences) == 0 {
		return nil, fmt.Errorf("at least one expected audience is required (prevents confused deputy attacks)")
	}

	// Parse and validate JWT without audience check first
	// (we'll validate audience manually to handle both string and array)
	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
	}

	token, err := jwt.Parse([]byte(tokenStr), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("validating JWT: %w", err)
	}

	claims := &Claims{
		Subject:   token.Subject(),
		Issuer:    token.Issuer(),
		Audience:  token.Audience(),
		ExpiresAt: token.Expiration(),
		Extra:     make(map[string]any),
	}

	// Extract "azp" (authorized party / client ID)
	if azp, ok := token.Get("azp"); ok {
		if s, ok := azp.(string); ok {
			claims.ClientID = s
		}
	}

	// Extract scopes from "scope" claim (space-separated string)
	if scopeVal, ok := token.Get("scope"); ok {
		if s, ok := scopeVal.(string); ok {
			claims.Scopes = strings.Fields(s)
		}
	}

	// Copy remaining private claims to Extra
	for k, v := range token.PrivateClaims() {
		if k != "azp" && k != "scope" {
			claims.Extra[k] = v
		}
	}

	// Built before the audience check (not after) so debug logging sees the
	// full decoded claim set on the audience-mismatch error path too — that
	// is exactly the case an operator most needs to see "what did the token
	// actually contain" for.
	if v.debugLogClaims {
		logDecodedClaims(claims)
	}

	// Manually validate audience: token must contain at least one expected audience
	if !audienceMatches(claims.Audience, audiences) {
		return nil, fmt.Errorf("validating JWT: none of expected audiences %v found in token audiences %v", audiences, claims.Audience)
	}

	return claims, nil
}

// logDecodedClaims emits the full decoded claim set (registered + Extra) at
// Debug level, run through redact.JSON as defense-in-depth. Gated behind
// JWKSVerifier.debugLogClaims — see WithDebugLogClaims.
func logDecodedClaims(claims *Claims) {
	dump := map[string]any{
		"sub":   claims.Subject,
		"iss":   claims.Issuer,
		"aud":   claims.Audience,
		"azp":   claims.ClientID,
		"scope": claims.Scopes,
		"exp":   claims.ExpiresAt,
	}
	for k, val := range claims.Extra {
		dump[k] = val
	}
	raw, err := json.Marshal(dump)
	if err != nil {
		slog.Debug("jwt-validation: decoded token claims (marshal failed)", "error", err)
		return
	}
	slog.Debug("jwt-validation: decoded token claims", "claims", json.RawMessage(redact.JSON(raw)))
}

// audienceMatches checks if any of the expected audiences is present in the token's audience claim.
func audienceMatches(tokenAudiences []string, expectedAudiences []string) bool {
	for _, expected := range expectedAudiences {
		for _, actual := range tokenAudiences {
			if actual == expected {
				return true
			}
		}
	}
	return false
}
