package zensframework

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// AuditAction represents the type of action performed
type AuditAction string

const (
	AuditActionInsert     AuditAction = "INSERT"
	AuditActionUpdate     AuditAction = "UPDATE"
	AuditActionDelete     AuditAction = "DELETE"
	AuditActionSoftDelete AuditAction = "SOFT_DELETE"
)

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID            uuid.UUID              `bson:"_id"`
	CollectionName string                `bson:"collectionName"`
	Action        AuditAction           `bson:"action"`
	DocumentID    interface{}           `bson:"documentId"`
	TenantID      uuid.UUID             `bson:"tenantId"`
	Before        interface{}           `bson:"before,omitempty"`
	After         interface{}           `bson:"after,omitempty"`
	Changes       map[string]interface{} `bson:"changes,omitempty"`
	Author        string                `bson:"author"`
	AuthorID      string                `bson:"authorId"`
	Timestamp     time.Time             `bson:"timestamp"`
	CorrelationID string                `bson:"correlationId"`
}

// AuditLogger handles audit logging
type AuditLogger struct {
	db         *mongo.Database
	collection *mongo.Collection
	enabled    bool
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(db *mongo.Database, enabled bool) *AuditLogger {
	return &AuditLogger{
		db:         db,
		collection: db.Collection("audit_logs"),
		enabled:    enabled,
	}
}

// LogInsert logs an insert operation
func (a *AuditLogger) LogInsert(ctx context.Context, collectionName string, documentID interface{}, document interface{}) error {
	if !a.enabled {
		return nil
	}

	entry := a.createAuditEntry(ctx, collectionName, documentID, AuditActionInsert)
	entry.After = document

	_, err := a.collection.InsertOne(ctx, entry)
	return err
}

// LogUpdate logs an update operation
func (a *AuditLogger) LogUpdate(ctx context.Context, collectionName string, documentID interface{}, before interface{}, after interface{}) error {
	if !a.enabled {
		return nil
	}

	entry := a.createAuditEntry(ctx, collectionName, documentID, AuditActionUpdate)
	entry.Before = before
	entry.After = after
	
	// Calculate changes
	beforeMap, ok1 := before.(map[string]interface{})
	afterMap, ok2 := after.(map[string]interface{})
	
	if ok1 && ok2 {
		changes := make(map[string]interface{})
		for k, v := range afterMap {
			if beforeVal, exists := beforeMap[k]; exists {
				if fmt.Sprintf("%v", beforeVal) != fmt.Sprintf("%v", v) {
					changes[k] = map[string]interface{}{
						"before": beforeVal,
						"after":  v,
					}
				}
			} else {
				changes[k] = map[string]interface{}{
					"before": nil,
					"after":  v,
				}
			}
		}
		entry.Changes = changes
	}

	_, err := a.collection.InsertOne(ctx, entry)
	return err
}

// LogDelete logs a delete operation
func (a *AuditLogger) LogDelete(ctx context.Context, collectionName string, documentID interface{}, document interface{}, isSoftDelete bool) error {
	if !a.enabled {
		return nil
	}

	action := AuditActionDelete
	if isSoftDelete {
		action = AuditActionSoftDelete
	}

	entry := a.createAuditEntry(ctx, collectionName, documentID, action)
	entry.Before = document

	_, err := a.collection.InsertOne(ctx, entry)
	return err
}

// createAuditEntry creates a base audit entry with common fields
func (a *AuditLogger) createAuditEntry(ctx context.Context, collectionName string, documentID interface{}, action AuditAction) *AuditEntry {
	entry := &AuditEntry{
		ID:            uuid.New(),
		CollectionName: collectionName,
		Action:        action,
		DocumentID:    documentID,
		Timestamp:     time.Now(),
		CorrelationID: GetContextHeader(ctx, XCORRELATIONID),
		Author:        GetContextHeader(ctx, XAUTHOR),
		AuthorID:      GetContextHeader(ctx, XAUTHORID),
	}

	// Try to get tenant ID
	if tenantId := GetContextHeader(ctx, XTENANTID, TTENANTID); tenantId != "" {
		if tid, err := uuid.Parse(tenantId); err == nil {
			entry.TenantID = tid
		}
	}

	return entry
}

// CreateAuditIndexes creates indexes for the audit collection
func (a *AuditLogger) CreateAuditIndexes(ctx context.Context) error {
	// Create indexes for efficient querying
	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "collectionName", Value: 1},
				{Key: "documentId", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "tenantId", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "timestamp", Value: -1},
			},
		},
		{
			Keys: bson.D{
				{Key: "action", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "authorId", Value: 1},
			},
		},
	}

	_, err := a.collection.Indexes().CreateMany(ctx, indexes)
	return err
}