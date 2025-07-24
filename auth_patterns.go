package zensframework

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// AuthEndpoints fornece endpoints para verificação de autenticação e permissões
type AuthEndpoints struct {
	jwtHelper    *JWTHelper
	groupManager *GroupManager
}

// NewAuthEndpoints cria uma nova instância de AuthEndpoints
func NewAuthEndpoints(jwtHelper *JWTHelper, groupManager *GroupManager) *AuthEndpoints {
	return &AuthEndpoints{
		jwtHelper:    jwtHelper,
		groupManager: groupManager,
	}
}

// RegisterAuthEndpoints registra os endpoints de autenticação
func (ae *AuthEndpoints) RegisterAuthEndpoints(router *gin.RouterGroup) {
	auth := router.Group("/api/auth")
	{
		auth.POST("/check-role", ae.CheckRole)
		auth.POST("/check-permission", ae.CheckPermission)
		auth.GET("/permissions", ae.GetUserPermissions)
	}
}

// CheckRole verifica se um usuário tem todas as roles especificadas
func (ae *AuthEndpoints) CheckRole(c *gin.Context) {
	// Parse request body
	var req CheckRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{
			Allowed: false,
			Message: "Authentication failed (1)", // Código 1: Erro de formato de requisição
		})
		return
	}

	// Verifica roles
	response := ae.jwtHelper.CheckRoles(c, req)
	c.JSON(http.StatusOK, response)
}

// CheckPermission verifica se um usuário tem todas as permissões especificadas
func (ae *AuthEndpoints) CheckPermission(c *gin.Context) {
	// Parse request body
	var req CheckPermissionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{
			Allowed: false,
			Message: "Authentication failed (1)", // Código 1: Erro de formato de requisição
		})
		return
	}

	// Get user ID
	userID, exists := GetUserID(c)
	if !exists {
		c.JSON(http.StatusOK, CheckResponse{
			Allowed: false,
			Message: "Authentication failed (2)", // Código 2: Usuário não autenticado
		})
		return
	}

	// Verifica permissões
	allowed, err := ae.groupManager.CheckUserPermissions(c, userID, req.Permissions)
	if err != nil {
		c.JSON(http.StatusOK, CheckResponse{
			Allowed: false,
			Message: "Authentication failed (3)", // Código 3: Erro ao verificar permissões
		})
		return
	}

	response := CheckResponse{
		Allowed: allowed,
	}

	if !allowed {
		response.Message = "Authentication failed (4)" // Código 4: Permissões insuficientes
	} else {
		response.Message = "Authentication successful"
	}

	c.JSON(http.StatusOK, response)
}

// GetUserPermissions retorna todas as permissões e roles de um usuário
func (ae *AuthEndpoints) GetUserPermissions(c *gin.Context) {
	// Get user ID
	userID, exists := GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed (2)"}) // Código 2: Usuário não autenticado
		return
	}

	// Get permissions from groups
	permissions, err := ae.groupManager.GetUserPermissions(c, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Authentication failed (5)"}) // Código 5: Erro ao obter permissões
		return
	}

	// Get roles from JWT claims
	roles := []string{}
	if userRoles, exists := c.Get("roles"); exists {
		if rolesList, ok := userRoles.([]string); ok {
			roles = rolesList
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"roles":       roles,
		"permissions": permissions,
	})
}

// CSRF Protection with Double Submit Cookie

// CSRFToken representa um token CSRF
type CSRFToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// GenerateCSRFToken gera um novo token CSRF
func GenerateCSRFToken() CSRFToken {
	token := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)
	return CSRFToken{
		Token:     token,
		ExpiresAt: expiresAt,
	}
}

// CSRFMiddleware cria um middleware para proteção CSRF com Double Submit Cookie
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ignora métodos seguros (GET, HEAD, OPTIONS)
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Obtém token do header X-CSRF-Token
		headerToken := c.GetHeader("X-CSRF-Token")
		
		// Obtém token do cookie CSRF
		cookieToken, err := c.Cookie("csrf_token")
		
		// Valida Double Submit Cookie: header e cookie devem existir e ser iguais
		if err != nil || headerToken == "" || cookieToken == "" || headerToken != cookieToken {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Authentication failed (6)", // Código 6: Token CSRF inválido
			})
			return
		}

		c.Next()
	}
}

// SetCSRFToken define um token CSRF como cookie e header
func SetCSRFToken(c *gin.Context) {
	csrfToken := GenerateCSRFToken()
	
	// Define cookie CSRF (HttpOnly = false para permitir leitura pelo JS)
	c.SetCookie(
		"csrf_token",
		csrfToken.Token,
		int(time.Hour.Seconds()),
		"/",
		"", // domain vazio para usar o domínio atual
		false, // secure = false para desenvolvimento
		false, // httpOnly = false para permitir acesso via JS
	)
	
	// Também retorna no header para facilitar o uso
	c.Header("X-CSRF-Token", csrfToken.Token)
}

// Rate Limiting

// RateLimiterConfig configura o rate limiter
type RateLimiterConfig struct {
	RequestsPerMinute int
	BurstSize         int
}

// DefaultRateLimiterConfig retorna uma configuração padrão para o rate limiter
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		RequestsPerMinute: 5,
		BurstSize:         5,
	}
}

// RateLimiterMiddleware cria um middleware para rate limiting
func RateLimiterMiddleware(config RateLimiterConfig) gin.HandlerFunc {
	// Cria um mapa para armazenar limiters por IP
	limiters := make(map[string]*rate.Limiter)
	
	return func(c *gin.Context) {
		// Obtém o IP do cliente
		clientIP := c.ClientIP()
		
		// Obtém ou cria um limiter para este IP
		limiter, exists := limiters[clientIP]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(config.RequestsPerMinute)/60, config.BurstSize)
			limiters[clientIP] = limiter
		}
		
		// Verifica se a requisição está dentro do limite
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Authentication failed (7)", // Código 7: Rate limit excedido
			})
			return
		}
		
		c.Next()
	}
}

// RegisterAuthEndpoints registra os endpoints de autenticação no framework
func (gf *GoFramework) RegisterAuthEndpoints() {
	gf.Invoke(func(jwtHelper *JWTHelper, groupManager *GroupManager, router *gin.RouterGroup) {
		endpoints := NewAuthEndpoints(jwtHelper, groupManager)
		endpoints.RegisterAuthEndpoints(router)
	})
}

// RegisterRateLimiter registra um middleware de rate limiting para uma rota específica
func (gf *GoFramework) RegisterRateLimiter(routerGroup *gin.RouterGroup, config RateLimiterConfig) {
	routerGroup.Use(RateLimiterMiddleware(config))
}

// RegisterCSRFProtection registra o middleware de proteção CSRF
func (gf *GoFramework) RegisterCSRFProtection(routerGroup *gin.RouterGroup) {
	routerGroup.Use(CSRFMiddleware())
	
	// Adiciona um endpoint para obter um token CSRF
	routerGroup.GET("/csrf-token", func(c *gin.Context) {
		SetCSRFToken(c)
		c.JSON(http.StatusOK, gin.H{"token": c.GetString("csrf_token")})
	})
}