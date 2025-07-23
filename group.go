package zensframework

import (
	"github.com/google/uuid"
)

// Group representa um grupo de permissões no sistema
type Group struct {
	ID          uuid.UUID `bson:"_id" json:"id"`
	Name        string    `bson:"name" json:"name"`
	Description string    `bson:"description" json:"description"`
	Permissions []string  `bson:"permissions" json:"permissions"`
	TenantID    uuid.UUID `bson:"tenantId" json:"tenantId"`
	Active      bool      `bson:"active" json:"active"`
}

// UserGroupMapping representa o relacionamento entre usuários e grupos
type UserGroupMapping struct {
	ID       uuid.UUID `bson:"_id" json:"id"`
	UserID   uuid.UUID `bson:"userId" json:"userId"`
	GroupID  uuid.UUID `bson:"groupId" json:"groupId"`
	TenantID uuid.UUID `bson:"tenantId" json:"tenantId"`
	Active   bool      `bson:"active" json:"active"`
}

// CheckRolesRequest representa uma requisição para verificar roles
type CheckRolesRequest struct {
	Roles []string `json:"roles" binding:"required"`
}

// CheckPermissionsRequest representa uma requisição para verificar permissões
type CheckPermissionsRequest struct {
	Permissions []string `json:"permissions" binding:"required"`
}

// CheckResponse representa a resposta da verificação de permissões ou roles
type CheckResponse struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message,omitempty"`
}