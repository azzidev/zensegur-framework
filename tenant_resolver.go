package zensegur

import (
	"errors"
	"strings"
)

// ResolveUserTenant resolve o tenant baseado no username (user@alias)
func (c *Client) ResolveUserTenant(username string) (*Client, string, error) {
	// Split username (user@alias)
	parts := strings.Split(username, "@")
	if len(parts) != 2 {
		return nil, "", errors.New("formato inválido. Use: usuario@empresa")
	}
	
	user := parts[0]
	alias := parts[1]

	// Buscar tenant_id pelo alias na collection global tenants
	var tenantDoc struct {
		TenantID string `firestore:"tenant_id"`
	}
	err := c.Repository("tenants").
		Where("alias", "==", alias).
		First(&tenantDoc)
	if err != nil {
		return nil, "", errors.New("empresa não encontrada")
	}

	// Retornar client com tenant e username limpo
	tenantClient := c.WithTenant(tenantDoc.TenantID)
	return tenantClient, user, nil
}