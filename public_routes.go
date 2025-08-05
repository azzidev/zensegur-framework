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

		if permissions, ok := claims["permissions"].([]interface{}); ok {
			permStrings := make([]string, len(permissions))
			for i, p := range permissions {
				if ps, ok := p.(string); ok {
					permStrings[i] = ps
				}
			}
			c.Set("permissions", permStrings)
		}

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