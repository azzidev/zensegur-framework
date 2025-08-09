package zensframework

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

// JWTMiddlewareConfig configures JWT middleware behavior
type JWTMiddlewareConfig struct {
	// PublicPaths are paths that don't require authentication
	PublicPaths []string
}

// IsPublicPath checks if a path is in the public paths list
func (c *JWTMiddlewareConfig) IsPublicPath(path string) bool {
	for _, publicPath := range c.PublicPaths {
		if strings.HasPrefix(path, publicPath) {
			return true
		}
	}
	return false
}

// AuthMiddlewareWithConfig creates a middleware for JWT authentication with configuration
func (h *JWTHelper) AuthMiddlewareWithConfig(config *JWTMiddlewareConfig, validateFunc func(*gin.Context, jwt.Claims) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for public paths
		if config != nil && config.IsPublicPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Get token
		tokenString := GetTokenFromRequest(c)
		if tokenString == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": ErrMissingToken.Error()})
			return
		}

		// Create empty claims to be filled by ParseWithClaims
		claims := jwt.MapClaims{}

		// Validate token
		err := h.ValidateToken(tokenString, claims)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": err.Error()})
			return
		}

		// ✅ SECURITY: Check token blacklist with FAIL-SAFE
		if blacklist, exists := c.Get("token_blacklist"); exists {
			if tb, ok := blacklist.(*TokenBlacklist); ok {
				isRevoked, err := tb.IsTokenRevoked(c.Request.Context(), tokenString)
				if err != nil {
					// ⚠️ FAIL-SAFE: Se blacklist não funciona, REJEITA token por segurança
					c.AbortWithStatusJSON(503, gin.H{"error": "Authentication service unavailable - token rejected for security"})
					return
				}
				if isRevoked {
					c.AbortWithStatusJSON(401, gin.H{"error": "Token has been revoked"})
					return
				}
			}
		}

		// Set claims in context
		c.Set("claims", claims)

		// Extract standard claims
		if sub, ok := claims["sub"].(string); ok {
			c.Set("user_id", sub)
		}
		if name, ok := claims["name"].(string); ok {
			c.Set("name", name)
		}
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if tenantID, ok := claims["tenant_id"].(string); ok {
			c.Set("tenant_id", tenantID)
			// Set tenant headers for downstream services
			c.Request.Header.Set(XTENANTID, tenantID)
			c.Request.Header.Set(TTENANTID, tenantID)
		}

		// Extract roles and permissions
		if roles, ok := claims["roles"].([]interface{}); ok {
			roleStrings := make([]string, len(roles))
			for i, r := range roles {
				if rs, ok := r.(string); ok {
					roleStrings[i] = rs
				}
			}
			c.Set("roles", roleStrings)
		}

		// Extract permissions - sempre define no context
	permissions := []string{}
	if permsInterface, exists := claims["permissions"]; exists && permsInterface != nil {
		if permsList, ok := permsInterface.([]interface{}); ok {
			permissions = make([]string, len(permsList))
			for i, p := range permsList {
				if ps, ok := p.(string); ok {
					permissions[i] = ps
				}
			}
		}
	}
	c.Set("permissions", permissions)

		// Set author headers for audit
		if name, ok := claims["name"].(string); ok {
			c.Request.Header.Set(XAUTHOR, name)
		}
		if sub, ok := claims["sub"].(string); ok {
			c.Request.Header.Set(XAUTHORID, sub)
		}

		// Call custom validation function if provided
		if validateFunc != nil {
			if err := validateFunc(c, claims); err != nil {
				c.AbortWithStatusJSON(403, gin.H{"error": err.Error()})
				return
			}
		}

		c.Next()
	}
}