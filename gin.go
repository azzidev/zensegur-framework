package zensegur

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

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

func GinCookieAuthMiddleware(validator JWTValidator, cookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(cookieName)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no auth cookie"})
			c.Abort()
			return
		}

		claims, err := validator(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
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

// Middlewares universais
func GinCORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "https://zensegur.com.br")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func GinSecurityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		
		// Validação de tamanho
		if c.Request.ContentLength > 5*1024*1024 { // 5MB
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request too large"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func GinRateLimitMiddleware(requests int, perSeconds int) gin.HandlerFunc {
	limiter := rate.NewLimiter(rate.Every(time.Duration(perSeconds)*time.Second/time.Duration(requests)), requests)
	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
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
