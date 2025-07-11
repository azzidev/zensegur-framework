package zensegur

import (
	"errors"
	"strings"
)

// JWT Claims interface para flexibilidade
type Claims interface {
	GetUserID() string
	GetUsername() string
	GetRoles() []string
	GetPermissions() []string
}

// Função de validação JWT customizável
type JWTValidator func(token string) (Claims, error)

// Context interface genérico para diferentes frameworks
type Context interface {
	GetHeader(key string) string
	Set(key string, value interface{})
	Get(key string) (interface{}, bool)
	Abort()
	JSON(code int, obj interface{})
}

// Função de autenticação genérica
func ValidateAuth(ctx Context, validator JWTValidator) (Claims, error) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return nil, ErrMissingAuth
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	return validator(token)
}

// Função de autorização por roles
func CheckRole(ctx Context, roles ...string) bool {
	userRoles, exists := ctx.Get("roles")
	if !exists {
		return false
	}

	rolesList := userRoles.([]string)
	for _, requiredRole := range roles {
		for _, userRole := range rolesList {
			if userRole == requiredRole {
				return true
			}
		}
	}
	return false
}

// Função de autorização por permissões
func CheckPermission(ctx Context, permissions ...string) bool {
	userPermissions, exists := ctx.Get("permissions")
	if !exists {
		return false
	}

	permissionsList := userPermissions.([]string)
	for _, requiredPerm := range permissions {
		for _, userPerm := range permissionsList {
			if userPerm == requiredPerm {
				return true
			}
		}
	}
	return false
}

// Erros
var (
	ErrMissingAuth = errors.New("authorization header required")
	ErrInvalidToken = errors.New("invalid token")
	ErrInsufficientPermissions = errors.New("insufficient permissions")
)