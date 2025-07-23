package zensframework

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// GroupManager gerencia operações relacionadas a grupos e permissões
type GroupManager struct {
	groupRepo   IRepository[Group]
	mappingRepo IRepository[UserGroupMapping]
}

// NewGroupManager cria um novo gerenciador de grupos
func NewGroupManager(
	groupRepo IRepository[Group],
	mappingRepo IRepository[UserGroupMapping],
) *GroupManager {
	return &GroupManager{
		groupRepo:   groupRepo,
		mappingRepo: mappingRepo,
	}
}

// GetUserGroups obtém todos os grupos de um usuário
func (m *GroupManager) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]Group, error) {
	// Busca mapeamentos do usuário
	filter := map[string]interface{}{"userId": userID, "active": true}
	mappings := m.mappingRepo.GetAll(ctx, filter)

	if mappings == nil || len(*mappings) == 0 {
		return []Group{}, nil
	}

	// Busca grupos
	groups := make([]Group, 0, len(*mappings))
	for _, mapping := range *mappings {
		groupFilter := map[string]interface{}{"_id": mapping.GroupID, "active": true}
		group := m.groupRepo.GetFirst(ctx, groupFilter)
		if group != nil {
			groups = append(groups, *group)
		}
	}

	return groups, nil
}

// GetUserPermissions obtém todas as permissões de um usuário baseado em seus grupos
func (m *GroupManager) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// Obtém grupos do usuário
	groups, err := m.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Extrai permissões únicas
	permissionsMap := make(map[string]bool)
	for _, group := range groups {
		for _, perm := range group.Permissions {
			permissionsMap[perm] = true
		}
	}

	// Converte mapa para slice
	permissions := make([]string, 0, len(permissionsMap))
	for perm := range permissionsMap {
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// CheckUserPermissions verifica se um usuário tem todas as permissões especificadas
func (m *GroupManager) CheckUserPermissions(ctx context.Context, userID uuid.UUID, requiredPermissions []string) (bool, error) {
	// Obtém permissões do usuário
	userPermissions, err := m.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	// Converte para mapa para busca eficiente
	permissionsMap := make(map[string]bool)
	for _, perm := range userPermissions {
		permissionsMap[perm] = true
	}

	// Verifica se o usuário tem todas as permissões requeridas
	for _, requiredPerm := range requiredPermissions {
		if !permissionsMap[requiredPerm] {
			return false, nil
		}
	}

	return true, nil
}

// AddUserToGroup adiciona um usuário a um grupo
func (m *GroupManager) AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	// Verifica se o grupo existe
	groupFilter := map[string]interface{}{"_id": groupID, "active": true}
	group := m.groupRepo.GetFirst(ctx, groupFilter)
	if group == nil {
		return errors.New("group not found")
	}

	// Verifica se o mapeamento já existe
	mappingFilter := map[string]interface{}{"userId": userID, "groupId": groupID}
	existingMapping := m.mappingRepo.GetFirst(ctx, mappingFilter)
	if existingMapping != nil {
		// Se já existe e está inativo, reativa
		if !existingMapping.Active {
			existingMapping.Active = true
			return m.mappingRepo.Update(ctx, mappingFilter, map[string]interface{}{"active": true})
		}
		return nil // Já existe e está ativo
	}

	// Cria novo mapeamento
	mapping := &UserGroupMapping{
		ID:       uuid.New(),
		UserID:   userID,
		GroupID:  groupID,
		TenantID: group.TenantID,
		Active:   true,
	}

	return m.mappingRepo.Insert(ctx, mapping)
}

// RemoveUserFromGroup remove um usuário de um grupo
func (m *GroupManager) RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	mappingFilter := map[string]interface{}{"userId": userID, "groupId": groupID}
	return m.mappingRepo.Delete(ctx, mappingFilter)
}

// RegisterGroupManager registra o gerenciador de grupos no framework
func (zsf *GoFramework) RegisterGroupManager(
	groupRepo IRepository[Group],
	mappingRepo IRepository[UserGroupMapping],
) {
	err := zsf.ioc.Provide(func() *GroupManager {
		return NewGroupManager(groupRepo, mappingRepo)
	})
	if err != nil {
		panic(err)
	}
}
