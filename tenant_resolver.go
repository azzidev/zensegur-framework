package zensegur

import (
	"context"
	"errors"
	"strings"
)

func (c *Client) ResolveUserTenant(username string) (*Client, string, error) {
	parts := strings.Split(username, "@")
	if len(parts) != 2 {
		return nil, "", errors.New("formato inválido. Use: usuario@empresa")
	}
	
	user := parts[0]
	alias := parts[1]

	filter := map[string]interface{}{
		"alias": alias,
	}
	ctx := context.Background()
	result := c.Repository("tenants").GetFirst(ctx, filter)
	if result == nil {
		return nil, "", errors.New("empresa não encontrada")
	}
	
	tenantMap := *result
	if tenantMap["tenant_id"] == nil {
		return nil, "", errors.New("dados de tenant inválidos")
	}
	
	tenantID, ok := tenantMap["tenant_id"].(string)
	if !ok {
		return nil, "", errors.New("tenant_id inválido")
	}

	tenantClient := c.WithTenant(tenantID)
	return tenantClient, user, nil
}