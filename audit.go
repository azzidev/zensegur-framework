package zensegur

import (
	"context"
	"fmt"
	"time"
)

type AuditLog struct {
	ID        string                 `bson:"_id,omitempty" json:"id"`
	Tenant    string                 `bson:"tenant" json:"tenant"`
	Action    string                 `bson:"action" json:"action"`
	Table     string                 `bson:"table" json:"table"`
	RecordID  string                 `bson:"record_id" json:"record_id"`
	UserID    string                 `bson:"user_id" json:"user_id"`
	Changes   map[string]interface{} `bson:"changes" json:"changes"`
	Timestamp time.Time              `bson:"timestamp" json:"timestamp"`
}

func (r *MongoRepository[T]) WithAudit(enabled bool) *MongoRepository[T] {
	clone := *r
	clone.auditLog = enabled
	return &clone
}

func (r *MongoRepository[T]) logAuditLegacy(ctx context.Context, action string, id interface{}, oldData, newData interface{}) {
	if r.userID == "" {
		return
	}

	audit := AuditLog{
		Tenant:    extractTenant(r.collection.Name()),
		Action:    action,
		Table:     r.collection.Name(),
		RecordID:  toString(id),
		UserID:    r.userID,
		Changes:   extractChanges(oldData, newData),
		Timestamp: time.Now(),
	}

	_, _ = r.database.Collection("audit_logs").InsertOne(ctx, audit)
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func extractChanges(oldData, newData interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	if oldData != nil {
		result["old"] = oldData
	}
	if newData != nil {
		result["new"] = newData
	}
	return result
}

func extractTenant(collection string) string {
	if len(collection) > 0 {
		parts := []rune(collection)
		for i, char := range parts {
			if char == '_' {
				return string(parts[:i])
			}
		}
	}
	return ""
}
