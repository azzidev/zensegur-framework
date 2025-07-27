package zensframework

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RolesSignature gera e verifica assinaturas para roles e permissions
type RolesSignature struct {
	secretKey string
}

// NewRolesSignature cria uma nova instância do gerador de assinaturas para roles
func NewRolesSignature(secretKey string) *RolesSignature {
	return &RolesSignature{
		secretKey: secretKey,
	}
}

// GenerateRolesSignature gera uma assinatura para roles de um usuário
func (rs *RolesSignature) GenerateRolesSignature(
	userID uuid.UUID,
	roles []string,
	timestamp time.Time,
) string {
	// Ordena roles para garantir consistência
	sortedRoles := make([]string, len(roles))
	copy(sortedRoles, roles)
	sort.Strings(sortedRoles)

	// Cria string para assinatura
	data := fmt.Sprintf("%s:%s:%d:%s", 
		userID.String(), 
		strings.Join(sortedRoles, ","), 
		timestamp.Unix(),
		rs.secretKey,
	)

	// Gera HMAC SHA256
	hash := hmac.New(sha256.New, []byte(rs.secretKey))
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyRolesSignature verifica se uma assinatura de roles é válida
func (rs *RolesSignature) VerifyRolesSignature(
	userID uuid.UUID,
	roles []string,
	timestamp time.Time,
	signature string,
) bool {
	expectedSignature := rs.GenerateRolesSignature(userID, roles, timestamp)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

// GeneratePermissionsSignature gera uma assinatura para permissions de um usuário
func (rs *RolesSignature) GeneratePermissionsSignature(
	userID uuid.UUID,
	permissions []string,
	timestamp time.Time,
) string {
	// Ordena permissions para garantir consistência
	sortedPerms := make([]string, len(permissions))
	copy(sortedPerms, permissions)
	sort.Strings(sortedPerms)

	// Cria string para assinatura
	data := fmt.Sprintf("%s:%s:%d:%s", 
		userID.String(), 
		strings.Join(sortedPerms, ","), 
		timestamp.Unix(),
		rs.secretKey,
	)

	// Gera HMAC SHA256
	hash := hmac.New(sha256.New, []byte(rs.secretKey))
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyPermissionsSignature verifica se uma assinatura de permissions é válida
func (rs *RolesSignature) VerifyPermissionsSignature(
	userID uuid.UUID,
	permissions []string,
	timestamp time.Time,
	signature string,
) bool {
	expectedSignature := rs.GeneratePermissionsSignature(userID, permissions, timestamp)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

// UserRolesData representa os dados de roles de um usuário com assinatura
type UserRolesData struct {
	UserID           uuid.UUID `bson:"userId" json:"userId"`
	Roles            []string  `bson:"roles" json:"roles"`
	RolesSignature   string    `bson:"rolesSignature" json:"rolesSignature"`
	RolesTimestamp   time.Time `bson:"rolesTimestamp" json:"rolesTimestamp"`
	Permissions      []string  `bson:"permissions" json:"permissions"`
	PermSignature    string    `bson:"permissionsSignature" json:"permissionsSignature"`
	PermTimestamp    time.Time `bson:"permissionsTimestamp" json:"permissionsTimestamp"`
	LastModifiedBy   string    `bson:"lastModifiedBy" json:"lastModifiedBy"`
}

// ValidateUserRoles valida as assinaturas de roles e permissions de um usuário
func (rs *RolesSignature) ValidateUserRoles(data *UserRolesData) (bool, bool) {
	rolesValid := rs.VerifyRolesSignature(
		data.UserID, 
		data.Roles, 
		data.RolesTimestamp, 
		data.RolesSignature,
	)

	permissionsValid := rs.VerifyPermissionsSignature(
		data.UserID, 
		data.Permissions, 
		data.PermTimestamp, 
		data.PermSignature,
	)

	return rolesValid, permissionsValid
}

// CreateSignedUserRoles cria dados de roles com assinaturas válidas
func (rs *RolesSignature) CreateSignedUserRoles(
	userID uuid.UUID,
	roles []string,
	permissions []string,
	modifiedBy string,
) *UserRolesData {
	now := time.Now()

	rolesSignature := rs.GenerateRolesSignature(userID, roles, now)
	permSignature := rs.GeneratePermissionsSignature(userID, permissions, now)

	return &UserRolesData{
		UserID:           userID,
		Roles:            roles,
		RolesSignature:   rolesSignature,
		RolesTimestamp:   now,
		Permissions:      permissions,
		PermSignature:    permSignature,
		PermTimestamp:    now,
		LastModifiedBy:   modifiedBy,
	}
}

// RegisterRolesSignature registra o gerador de assinaturas de roles no framework
func (zsf *ZSFramework) RegisterRolesSignature(secretKey string) {
	err := zsf.ioc.Provide(func() *RolesSignature {
		return NewRolesSignature(secretKey)
	})
	if err != nil {
		panic(err)
	}
}