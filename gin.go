package zensegur

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Adapter para Gin Context
type GinContext struct {
	*gin.Context
}

func (g *GinContext) GetHeader(key string) string {
	return g.Context.GetHeader(key)
}

func (g *GinContext) Set(key string, value interface{}) {
	g.Context.Set(key, value)
}

func (g *GinContext) Get(key string) (interface{}, bool) {
	return g.Context.Get(key)
}

func (g *GinContext) Abort() {
	g.Context.Abort()
}

func (g *GinContext) JSON(code int, obj interface{}) {
	g.Context.JSON(code, obj)
}

// Middleware Gin específico
func GinAuthMiddleware(validator JWTValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := &GinContext{c}
		claims, err := ValidateAuth(ctx, validator)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Adiciona claims no contexto
		c.Set("user_id", claims.GetUserID())
		c.Set("username", claims.GetUsername())
		c.Set("roles", claims.GetRoles())
		c.Set("permissions", claims.GetPermissions())
		c.Set("claims", claims)

		c.Next()
	}
}

func GinRequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := &GinContext{c}
		if !CheckRole(ctx, roles...) {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func GinRequirePermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := &GinContext{c}
		if !CheckPermission(ctx, permissions...) {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// Helpers para Gin
func GinGetUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		return userID.(string)
	}
	return ""
}

func GinGetUsername(c *gin.Context) string {
	if username, exists := c.Get("username"); exists {
		return username.(string)
	}
	return ""
}