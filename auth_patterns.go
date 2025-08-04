package zensframework

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
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

	// ✅ Lê permissions do JWT em vez do banco
	userPerms, exists := c.Get("permissions")
	if !exists {
		c.JSON(http.StatusOK, CheckResponse{
			Allowed: false,
			Message: "Authentication failed (2)", // Código 2: Usuário não autenticado
		})
		return
	}

	userPermissions, ok := userPerms.([]string)
	if !ok {
		c.JSON(http.StatusOK, CheckResponse{
			Allowed: false,
			Message: "Authentication failed (3)", // Código 3: Formato de permissions inválido
		})
		return
	}

	// Converte para mapa para busca eficiente
	permissionsMap := make(map[string]bool)
	for _, perm := range userPermissions {
		permissionsMap[perm] = true
	}

	// Verifica se o usuário tem todas as permissões requeridas
	allowed := true
	for _, requiredPerm := range req.Permissions {
		if !permissionsMap[requiredPerm] {
			allowed = false
			break
		}
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
	// ✅ Lê roles do JWT
	roles := []string{}
	if userRoles, exists := c.Get("roles"); exists {
		if rolesList, ok := userRoles.([]string); ok {
			roles = rolesList
		}
	}

	// ✅ Lê permissions do JWT em vez do banco
	permissions := []string{}
	if userPerms, exists := c.Get("permissions"); exists {
		if permsList, ok := userPerms.([]string); ok {
			permissions = permsList
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
		"",    // domain vazio para usar o domínio atual
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
func (zsf *ZSFramework) RegisterAuthEndpoints() {
	// Criar repositórios padrão se não existirem
	zsf.Invoke(func(db *mongo.Database, monitoring *Monitoring, v *viper.Viper) {
		// Criar repositórios padrão para grupos
		groupRepo := NewMongoDbRepository[Group](db, monitoring, v)
		groupRepo.ChangeCollection("zsf_groups")
		
		mappingRepo := NewMongoDbRepository[UserGroupMapping](db, monitoring, v)
		mappingRepo.ChangeCollection("zsf_user_group_mappings")
		
		// Registrar GroupManager com repositórios padrão
		zsf.RegisterGroupManager(groupRepo, mappingRepo)
	})
	
	// Agora registrar os endpoints
	zsf.Invoke(func(jwtHelper *JWTHelper, groupManager *GroupManager, router *gin.RouterGroup) {
		endpoints := NewAuthEndpoints(jwtHelper, groupManager)
		endpoints.RegisterAuthEndpoints(router)
	})
}

// RegisterRateLimiter registra um middleware de rate limiting para uma rota específica
func (zsf *ZSFramework) RegisterRateLimiter(routerGroup *gin.RouterGroup, config RateLimiterConfig) {
	routerGroup.Use(RateLimiterMiddleware(config))
}

// RegisterCSRFProtection registra o middleware de proteção CSRF
func (zsf *ZSFramework) RegisterCSRFProtection(routerGroup *gin.RouterGroup) {
	routerGroup.Use(CSRFMiddleware())

	// Adiciona um endpoint para obter um token CSRF
	routerGroup.GET("/csrf-token", func(c *gin.Context) {
		SetCSRFToken(c)
		c.JSON(http.StatusOK, gin.H{"token": c.GetString("csrf_token")})
	})
}
