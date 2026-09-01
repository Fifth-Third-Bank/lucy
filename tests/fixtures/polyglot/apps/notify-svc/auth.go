package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Bearer-token verification for notify-svc. RS256 only: the verification
// key is provisioned through the environment, HMAC tokens are rejected,
// and issuer, audience, and expiry are all enforced on every request.

const (
	expectedIssuer   = "https://auth.example.invalid/realms/demo"
	expectedAudience = "notify-svc"
)

type contextKey string

const tenantContextKey contextKey = "tenant_id"

// loadVerifyKey reads the RS256 public key from the environment. There is
// no embedded fallback key; missing configuration fails closed at boot.
func loadVerifyKey() (*rsa.PublicKey, error) {
	pemData := os.Getenv("AUTH_PUBLIC_KEY_PEM")
	if pemData == "" {
		return nil, errors.New("AUTH_PUBLIC_KEY_PEM is required")
	}
	return jwt.ParseRSAPublicKeyFromPEM([]byte(pemData))
}

// authMiddleware rejects any request without a valid bearer token and
// stores the verified tenant binding in the request context.
func authMiddleware(key *rsa.PublicKey, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}
		raw := strings.TrimPrefix(header, "Bearer ")

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(raw, claims,
			func(token *jwt.Token) (any, error) {
				// Pin the algorithm family: an HS256 token signed with the
				// public key bytes must never verify.
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, errors.New("unexpected signing method")
				}
				return key, nil
			},
			jwt.WithIssuer(expectedIssuer),
			jwt.WithAudience(expectedAudience),
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{"RS256"}),
		)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		tenantID, _ := claims["tenant_id"].(string)
		if tenantID == "" {
			http.Error(w, `{"error":"no tenant binding"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), tenantContextKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// tenantFrom returns the verified tenant id placed by authMiddleware.
func tenantFrom(ctx context.Context) string {
	tenantID, _ := ctx.Value(tenantContextKey).(string)
	return tenantID
}
