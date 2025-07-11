package zensegur

import (
	"context"
	"time"
)

type AuditLog struct {
	ID        string                 `firestore:"id"`
	Tenant    string                 `firestore:"tenant"`
	Action    string                 `firestore:"action"`
	Table     string                 `firestore:"table"`
	RecordID  string                 `firestore:"record_id"`
	UserID    string                 `firestore:"user_id"`
	Changes   map[string]interface{} `firestore:"changes"`
	Timestamp time.Time              `firestore:"timestamp"`
}

func (r *Repository) WithAudit(userID string) *Repository {
	return &Repository{
		client:     r.client,
		collection: r.collection,
		ctx:        context.WithValue(r.ctx, "audit_user", userID),
	}
}

func (r *Repository) logAudit(action, recordID string, changes map[string]interface{}) {
	userID, _ := r.ctx.Value("audit_user").(string)
	if userID == "" {
		return
	}

	audit := AuditLog{
		Tenant:    extractTenant(r.collection),
		Action:    action,
		Table:     r.collection,
		RecordID:  recordID,
		UserID:    userID,
		Changes:   changes,
		Timestamp: time.Now(),
	}

	auditRepo := NewRepository(r.client, "audit_logs")
	auditRepo.Create(audit)
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
