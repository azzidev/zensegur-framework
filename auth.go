package zensframework

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// Auth errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidToken       = errors.New("invalid token")
	ErrMissingToken       = errors.New("missing token")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
)

// JWTConfig represents JWT configuration
type JWTConfig struct {
	Secret         string        `json:"secret"`
	AccessExpiry   time.Duration `json:"accessExpiry"`
	RefreshExpiry  time.Duration `json:"refreshExpiry"`
	CookieDomain   string        `json:"cookieDomain"`
	CookieSecure   bool          `json:"cookieSecure"`
	CookieHTTPOnly bool          `json:"cookieHttpOnly"`
	CookieSameSite http.SameSite `json:"cookieSameSite"`
	Issuer         string        `json:"issuer"`
	BcryptCost     int           `json:"bcryptCost"`
}

// JWTHelper provides JWT utilities
type JWTHelper struct {
	config *JWTConfig
}

// NewJWTHelper creates a new JWT helper
func NewJWTHelper(config *JWTConfig) *JWTHelper {
	if config.BcryptCost <= 0 {
		config.BcryptCost = 14
	}

	return &JWTHelper{
		config: config,
	}
}

// HashPassword creates a bcrypt hash from a password
func HashPassword(password string) (string, error) {
	return HashPasswordWithCost(password, 14)
}

// HashPasswordWithCost creates a bcrypt hash with specified cost factor
func HashPasswordWithCost(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = 14 // Default cost if invalid
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(bytes), err
}

// CheckPassword compares a password with a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken generates a JWT token with the given claims
func (h *JWTHelper) GenerateToken(claims jwt.Claims, expiry time.Duration) (string, error) {
	if h.config.Issuer != "" {
		if mapClaims, ok := claims.(jwt.MapClaims); ok {
			// Add issuer
			if _, exists := mapClaims["iss"]; !exists {
				mapClaims["iss"] = h.config.Issuer
			}
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.config.Secret))
}

// ValidateToken validates a JWT token and returns the claims
func (h *JWTHelper) ValidateToken(tokenString string, claims jwt.Claims) error {
	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.config.Secret), nil
	})

	// Handle parsing errors
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return ErrTokenExpired
			}
		}
		return ErrInvalidToken
	}

	if !token.Valid {
		return ErrInvalidToken
	}

	// Verify issuer
	if h.config.Issuer != "" {
		if mapClaims, ok := claims.(jwt.MapClaims); ok {
			if issuer, ok := mapClaims["iss"].(string); !ok || issuer != h.config.Issuer {
				return ErrInvalidToken
			}
		}
	}

	return nil
}

// SetAuthCookies sets authentication cookies
func (h *JWTHelper) SetAuthCookies(c *gin.Context, accessToken, refreshToken string) {
	// Set access token cookie
	c.SetCookie(
		"access_token",
		accessToken,
		int(h.config.AccessExpiry.Seconds()),
		"/",
		h.config.CookieDomain,
		h.config.CookieSecure,
		h.config.CookieHTTPOnly,
	)

	// Set refresh token cookie
	c.SetCookie(
		"refresh_token",
		refreshToken,
		int(h.config.RefreshExpiry.Seconds()),
		"/",
		h.config.CookieDomain,
		h.config.CookieSecure,
		h.config.CookieHTTPOnly,
	)

	// Set SameSite policy
	c.Writer.Header().Set("Set-Cookie", fmt.Sprintf("SameSite=%s", h.config.CookieSameSite))
}

// ClearAuthCookies clears authentication cookies
func (h *JWTHelper) ClearAuthCookies(c *gin.Context) {
	c.SetCookie("access_token", "", -1, "/", h.config.CookieDomain, h.config.CookieSecure, h.config.CookieHTTPOnly)
	c.SetCookie("refresh_token", "", -1, "/", h.config.CookieDomain, h.config.CookieSecure, h.config.CookieHTTPOnly)
}

// GetTokenFromRequest extracts token from request, prioritizing cookie over header
func GetTokenFromRequest(c *gin.Context) string {
	// Get token from cookie first (prioritize HttpOnly cookie)
	token, err := c.Cookie("access_token")
	if err == nil && token != "" {
		return token
	}

	// Fallback to Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

// AuthMiddleware creates a middleware for JWT authentication
func (h *JWTHelper) AuthMiddleware(validateFunc func(*gin.Context, jwt.Claims) error) gin.HandlerFunc {
	// Use the new implementation with nil config (no public paths)
	return h.AuthMiddlewareWithConfig(nil, validateFunc)
}

// RequirePermission creates a middleware that requires at least one of the specified permissions
func (h *JWTHelper) RequirePermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get permissions from context
		userPerms, exists := c.Get("permissions")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"allowed": false,
				"message": ErrUnauthorized.Error(),
			})
			return
		}

		userPermissions, ok := userPerms.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"allowed": false,
				"message": "invalid permissions format",
			})
			return
		}

		// Check if user has any of the required permissions
		hasPermission := false
		for _, required := range permissions {
			for _, userPerm := range userPermissions {
				if required == userPerm {
					hasPermission = true
					break
				}
			}
			if hasPermission {
				break
			}
		}

		if !hasPermission {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"allowed": false,
				"message": "User does not have any of the required permissions",
			})
			return
		}

		c.Next()
	}
}

// RequireRole creates a middleware that requires at least one of the specified roles
func (h *JWTHelper) RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get roles from context
		userRoles, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"allowed": false,
				"message": ErrUnauthorized.Error(),
			})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"allowed": false,
				"message": "invalid roles format",
			})
			return
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, required := range roles {
			for _, userRole := range userRolesList {
				if required == userRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"allowed": false,
				"message": "User does not have any of the required roles",
			})
			return
		}

		c.Next()
	}
}

// RegisterJWTHelper registers the JWT helper with the framework
func (zsf *GoFramework) RegisterJWTHelper(config *JWTConfig) {
	err := zsf.ioc.Provide(func() *JWTHelper {
		return NewJWTHelper(config)
	})
	if err != nil {
		log.Panic(err)
	}
}

// RegisterGroupRepository registers a repository for groups
func (zsf *GoFramework) RegisterGroupRepository(constructor interface{}) {
	err := zsf.ioc.Provide(constructor)
	if err != nil {
		log.Panic(err)
	}
}

// RegisterUserGroupMappingRepository registers a repository for user-group mappings
func (zsf *GoFramework) RegisterUserGroupMappingRepository(constructor interface{}) {
	err := zsf.ioc.Provide(constructor)
	if err != nil {
		log.Panic(err)
	}
}
