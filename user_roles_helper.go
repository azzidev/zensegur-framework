package zensframework

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserRolesHelper gerencia roles e permissions de usuários com segurança
type UserRolesHelper struct {
	rolesSignature *RolesSignature
	groupManager   *GroupManager
}

// NewUserRolesHelper cria um novo helper para roles de usuários
func NewUserRolesHelper(rolesSignature *RolesSignature, groupManager *GroupManager) *UserRolesHelper {
	return &UserRolesHelper{
		rolesSignature: rolesSignature,
		groupManager:   groupManager,
	}
}

// GetUserRolesAndPermissions obtém roles e permissions de um usuário de forma segura
func (urh *UserRolesHelper) GetUserRolesAndPermissions(
	ctx context.Context,
	userID uuid.UUID,
	userRolesData *UserRolesData,
) ([]string, []string, error) {
	// Valida assinaturas
	rolesValid, permissionsValid := urh.rolesSignature.ValidateUserRoles(userRolesData)

	var finalRoles []string
	var finalPermissions []string

	// Se roles são válidas, usa elas
	if rolesValid {
		finalRoles = userRolesData.Roles
	} else {
		// Se assinatura inválida, ignora roles e usa apenas ["USER"] como fallback
		finalRoles = []string{"USER"}
	}

	// Se permissions são válidas, usa elas
	if permissionsValid {
		finalPermissions = userRolesData.Permissions
	}

	// Sempre adiciona permissions dos grupos (mesmo se roles/permissions diretas forem inválidas)
	if urh.groupManager != nil {
		groupPermissions, err := urh.groupManager.GetUserPermissions(ctx, userID)
		if err == nil {
			// Combina permissions diretas com permissions dos grupos
			permissionsMap := make(map[string]bool)
			
			// Adiciona permissions diretas (se válidas)
			for _, perm := range finalPermissions {
				permissionsMap[perm] = true
			}
			
			// Adiciona permissions dos grupos
			for _, perm := range groupPermissions {
				permissionsMap[perm] = true
			}
			
			// Converte de volta para slice
			finalPermissions = make([]string, 0, len(permissionsMap))
			for perm := range permissionsMap {
				finalPermissions = append(finalPermissions, perm)
			}
		}
	}

	return finalRoles, finalPermissions, nil
}

// UpdateUserRoles atualiza roles de um usuário com nova assinatura
func (urh *UserRolesHelper) UpdateUserRoles(
	userID uuid.UUID,
	newRoles []string,
	modifiedBy string,
) (*UserRolesData, error) {
	// Valida roles permitidas
	allowedRoles := []string{"MASTER", "ADMIN", "USER", "EXTERNAL"}
	for _, role := range newRoles {
		isAllowed := false
		for _, allowed := range allowedRoles {
			if role == allowed {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return nil, fmt.Errorf("role '%s' is not allowed", role)
		}
	}

	now := time.Now()
	rolesSignature := urh.rolesSignature.GenerateRolesSignature(userID, newRoles, now)

	return &UserRolesData{
		UserID:         userID,
		Roles:          newRoles,
		RolesSignature: rolesSignature,
		RolesTimestamp: now,
		LastModifiedBy: modifiedBy,
	}, nil
}

// UpdateUserPermissions atualiza permissions de um usuário com nova assinatura
func (urh *UserRolesHelper) UpdateUserPermissions(
	userID uuid.UUID,
	newPermissions []string,
	modifiedBy string,
) (*UserRolesData, error) {
	now := time.Now()
	permSignature := urh.rolesSignature.GeneratePermissionsSignature(userID, newPermissions, now)

	return &UserRolesData{
		UserID:        userID,
		Permissions:   newPermissions,
		PermSignature: permSignature,
		PermTimestamp: now,
		LastModifiedBy: modifiedBy,
	}, nil
}

// CreateJWTClaims cria claims JWT com roles e permissions validadas
func (urh *UserRolesHelper) CreateJWTClaims(
	ctx context.Context,
	userID uuid.UUID,
	userName, userEmail string,
	tenantID uuid.UUID,
	userRolesData *UserRolesData,
) (map[string]interface{}, error) {
	// Obtém roles e permissions validadas
	roles, permissions, err := urh.GetUserRolesAndPermissions(ctx, userID, userRolesData)
	if err != nil {
		return nil, err
	}

	// Cria claims JWT
	claims := map[string]interface{}{
		"sub":         userID.String(),
		"name":        userName,
		"email":       userEmail,
		"tenant_id":   tenantID.String(),
		"roles":       roles,
		"permissions": permissions,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	}

	return claims, nil
}

// RegisterUserRolesHelper registra o helper no framework
func (zsf *ZSFramework) RegisterUserRolesHelper() {
	err := zsf.ioc.Provide(func(rolesSignature *RolesSignature, groupManager *GroupManager) *UserRolesHelper {
		return NewUserRolesHelper(rolesSignature, groupManager)
	})
	if err != nil {
		panic(err)
	}
}