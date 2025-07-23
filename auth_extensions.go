package zensframework

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CheckRoles verifica se um usuário tem todas as roles especificadas
func (h *JWTHelper) CheckRoles(c *gin.Context, req CheckRolesRequest) CheckResponse {
	// Get roles from context
	userRoles, exists := c.Get("roles")
	if !exists {
		return CheckResponse{
			Allowed: false,
			Message: "User has no roles",
		}
	}

	userRolesList, ok := userRoles.([]string)
	if !ok {
		return CheckResponse{
			Allowed: false,
			Message: "Invalid roles format",
		}
	}

	// Converte roles do usuário para um mapa para busca mais eficiente
	userRolesMap := make(map[string]bool)
	for _, role := range userRolesList {
		userRolesMap[role] = true
	}

	// Verifica se o usuário tem todas as roles requeridas
	for _, requiredRole := range req.Roles {
		if !userRolesMap[requiredRole] {
			return CheckResponse{
				Allowed: false,
				Message: "User does not have all required roles",
			}
		}
	}

	return CheckResponse{
		Allowed: true,
		Message: "User has all required roles",
	}
}

// RequireAllRoles cria um middleware que requer que o usuário tenha todas as roles especificadas
func (h *JWTHelper) RequireAllRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get roles from context
		userRoles, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrUnauthorized.Error()})
			return
		}

		userRolesList, ok := userRoles.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid roles format"})
			return
		}

		// Converte roles do usuário para um mapa para busca mais eficiente
		userRolesMap := make(map[string]bool)
		for _, role := range userRolesList {
			userRolesMap[role] = true
		}

		// Verifica se o usuário tem todas as roles requeridas
		for _, requiredRole := range roles {
			if !userRolesMap[requiredRole] {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"allowed": false,
					"message": "User does not have all required roles",
				})
				return
			}
		}

		c.Next()
	}
}

// RequireAllPermissions cria um middleware que requer que o usuário tenha todas as permissões especificadas
func (h *JWTHelper) RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get permissions from context
		userPerms, exists := c.Get("permissions")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": ErrUnauthorized.Error()})
			return
		}

		userPermsList, ok := userPerms.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid permissions format"})
			return
		}

		// Converte permissões do usuário para um mapa para busca mais eficiente
		userPermsMap := make(map[string]bool)
		for _, perm := range userPermsList {
			userPermsMap[perm] = true
		}

		// Verifica se o usuário tem todas as permissões requeridas
		for _, requiredPerm := range permissions {
			if !userPermsMap[requiredPerm] {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"allowed": false,
					"message": "User does not have all required permissions",
				})
				return
			}
		}

		c.Next()
	}
}

// GetUserID extrai o ID do usuário do contexto
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, false
	}

	userIDStr, ok := userID.(string)
	if !ok {
		return uuid.Nil, false
	}

	id, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, false
	}

	return id, true
}