package zensframework

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
			Message: err.Error(),
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
			Message: err.Error(),
		})
		return
	}

	// Get user ID
	userID, exists := GetUserID(c)
	if !exists {
		c.JSON(http.StatusOK, CheckResponse{
			Allowed: false,
			Message: "Not authenticated",
		})
		return
	}

	// Verifica permissões
	allowed, err := ae.groupManager.CheckUserPermissions(c, userID, req.Permissions)
	if err != nil {
		c.JSON(http.StatusOK, CheckResponse{
			Allowed: false,
			Message: err.Error(),
		})
		return
	}

	response := CheckResponse{
		Allowed: allowed,
	}

	if !allowed {
		response.Message = "User does not have all required permissions"
	} else {
		response.Message = "User has all required permissions"
	}

	c.JSON(http.StatusOK, response)
}

// GetUserPermissions retorna todas as permissões de um usuário
func (ae *AuthEndpoints) GetUserPermissions(c *gin.Context) {
	// Get user ID
	userID, exists := GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Get permissions
	permissions, err := ae.groupManager.GetUserPermissions(c, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"permissions": permissions})
}

// RegisterAuthEndpoints registra os endpoints de autenticação no framework
func (zsf *GoFramework) RegisterAuthEndpoints() {
	zsf.Invoke(func(jwtHelper *JWTHelper, groupManager *GroupManager, router *gin.RouterGroup) {
		endpoints := NewAuthEndpoints(jwtHelper, groupManager)
		endpoints.RegisterAuthEndpoints(router)
	})
}
