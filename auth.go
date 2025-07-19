package zensegur

import (
	"context"
	"net/http"
	"strings"
)

type AuthContext interface {
	GetHeader(string) string
	Set(string, interface{})
	Abort()
	JSON(int, interface{})
}

func SetAuthCookie(w http.ResponseWriter, token string, maxAge int) {
	cookie := &http.Cookie{
		Name:     "auth-token",
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

func GetAuthCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("auth-token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func AuthMiddleware(validator JWTValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}

			token := parts[1]
			claims, err := validator(token)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "user_id", claims.GetUserID())
			ctx = context.WithValue(ctx, "username", claims.GetUsername())
			ctx = context.WithValue(ctx, "roles", claims.GetRoles())
			ctx = context.WithValue(ctx, "permissions", claims.GetPermissions())
			ctx = context.WithValue(ctx, "claims", claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
