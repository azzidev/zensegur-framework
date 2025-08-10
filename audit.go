package zensframework

import (
	"context"
	"reflect"
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

// AuditEntry represents an audit log entry for MongoDB
type AuditEntry struct {
	ID             uuid.UUID              `bson:"_id"`
	CollectionName string                 `bson:"collectionName"`
	Action         AuditAction            `bson:"action"`
	DocumentID     uuid.UUID              `bson:"documentId"`
	TenantID       uuid.UUID              `bson:"tenantId"`
	Before         interface{}            `bson:"before,omitempty"`
	After          interface{}            `bson:"after,omitempty"`
	Changes        map[string]interface{} `bson:"changes,omitempty"`
	Author         string                 `bson:"author"`
	AuthorID       string                 `bson:"authorId"`
	Timestamp      time.Time              `bson:"timestamp"`
	CorrelationID  uuid.UUID              `bson:"correlationId"`
}

// AuditEvent represents an audit event for PubSub
type AuditEvent struct {
	ID             uuid.UUID              `json:"id"`
	ServiceName    string                 `json:"serviceName"`
	CollectionName string                 `json:"collectionName"`
	Action         AuditAction            `json:"action"`
	DocumentID     uuid.UUID              `json:"documentId"`
	TenantID       uuid.UUID              `json:"tenantId"`
	Before         interface{}            `json:"before,omitempty"`
	After          interface{}            `json:"after,omitempty"`
	Changes        map[string]interface{} `json:"changes,omitempty"`
	Author         string                 `json:"author"`
	AuthorID       string                 `json:"authorId"`
	Timestamp      time.Time              `json:"timestamp"`
	CorrelationID  uuid.UUID              `json:"correlationId"`
}

// AuditPublisher interface for publishing audit events
type AuditPublisher interface {
	PublishAuditEvent(ctx context.Context, event *AuditEvent) error
}

// PubSubAuditPublisher implements AuditPublisher using PubSub
type PubSubAuditPublisher struct {
	producer PubSubProducer[AuditEvent]
}

// PublishAuditEvent publishes an audit event to PubSub
func (p *PubSubAuditPublisher) PublishAuditEvent(ctx context.Context, event *AuditEvent) error {
	if p.producer == nil {
		return nil
	}
	return p.producer.Publish(ctx, event)
}

// AuditLogger handles audit logging
type AuditLogger struct {
	db          *mongo.Database
	collection  *mongo.Collection
	enabled     bool
	publisher   AuditPublisher
	serviceName string
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(db *mongo.Database, enabled bool) *AuditLogger {
	return &AuditLogger{
		db:         db,
		collection: db.Collection("audit_logs"),
		enabled:    enabled,
	}
}

// NewAuditLoggerWithPublisher creates a new audit logger with PubSub publisher
func NewAuditLoggerWithPublisher(db *mongo.Database, enabled bool, serviceName string, publisher AuditPublisher) *AuditLogger {
	return &AuditLogger{
		db:          db,
		collection:  db.Collection("audit_logs"),
		enabled:     enabled,
		publisher:   publisher,
		serviceName: serviceName,
	}
}

// LogInsert logs an insert operation
func (a *AuditLogger) LogInsert(ctx context.Context, collectionName string, documentID interface{}, document interface{}) error {
	if !a.enabled {
		return nil
	}

	// Use PubSub if available (async)
	if a.publisher != nil {
		event := a.createAuditEvent(ctx, collectionName, documentID, AuditActionInsert)
		event.After = document
		return a.publisher.PublishAuditEvent(ctx, event)
	}

	// Fallback to direct MongoDB (sync)
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

	// Calculate changes
	var changes map[string]interface{}
	beforeMap, ok1 := before.(map[string]interface{})
	afterMap, ok2 := after.(map[string]interface{})

	if ok1 && ok2 {
		changes = make(map[string]interface{})
		for k, v := range afterMap {
			if beforeVal, exists := beforeMap[k]; exists {
				if !reflect.DeepEqual(beforeVal, v) {
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
	}

	// Use PubSub if available (async)
	if a.publisher != nil {
		event := a.createAuditEvent(ctx, collectionName, documentID, AuditActionUpdate)
		event.Before = before
		event.After = after
		event.Changes = changes
		return a.publisher.PublishAuditEvent(ctx, event)
	}

	// Fallback to direct MongoDB (sync)
	entry := a.createAuditEntry(ctx, collectionName, documentID, AuditActionUpdate)
	entry.Before = before
	entry.After = after
	entry.Changes = changes

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

	// Use PubSub if available (async)
	if a.publisher != nil {
		event := a.createAuditEvent(ctx, collectionName, documentID, action)
		event.Before = document
		return a.publisher.PublishAuditEvent(ctx, event)
	}

	// Fallback to direct MongoDB (sync)
	entry := a.createAuditEntry(ctx, collectionName, documentID, action)
	entry.Before = document

	_, err := a.collection.InsertOne(ctx, entry)
	return err
}

// parseCorrelationID converts string to UUID, generates new if invalid
func parseCorrelationID(correlationStr string) uuid.UUID {
	if correlationStr == "" {
		return uuid.New()
	}
	if correlationID, err := uuid.Parse(correlationStr); err == nil {
		return correlationID
	}
	return uuid.New()
}

// createAuditEntry creates a base audit entry with common fields
func (a *AuditLogger) createAuditEntry(ctx context.Context, collectionName string, documentID interface{}, action AuditAction) *AuditEntry {
	entry := &AuditEntry{
		ID:             uuid.New(),
		CollectionName: collectionName,
		Action:         action,
		DocumentID:     documentID.(uuid.UUID),
		Timestamp:      time.Now(),
		CorrelationID:  parseCorrelationID(GetContextHeader(ctx, XCORRELATIONID)),
		Author:         GetContextHeader(ctx, XAUTHOR),
		AuthorID:       GetContextHeader(ctx, XAUTHORID),
	}

	// Try to get tenant ID
	if tenantId := GetContextHeader(ctx, XTENANTID, TTENANTID); tenantId != "" {
		if tid, err := uuid.Parse(tenantId); err == nil {
			entry.TenantID = tid
		}
	}

	return entry
}

// createAuditEvent creates a base audit event for PubSub with common fields
func (a *AuditLogger) createAuditEvent(ctx context.Context, collectionName string, documentID interface{}, action AuditAction) *AuditEvent {
	event := &AuditEvent{
		ID:             uuid.New(),
		ServiceName:    a.serviceName,
		CollectionName: collectionName,
		Action:         action,
		DocumentID:     documentID.(uuid.UUID),
		Timestamp:      time.Now(),
		CorrelationID:  parseCorrelationID(GetContextHeader(ctx, XCORRELATIONID)),
		Author:         GetContextHeader(ctx, XAUTHOR),
		AuthorID:       GetContextHeader(ctx, XAUTHORID),
	}

	// Try to get tenant ID
	if tenantId := GetContextHeader(ctx, XTENANTID, TTENANTID); tenantId != "" {
		if tid, err := uuid.Parse(tenantId); err == nil {
			event.TenantID = tid
		}
	}

	return event
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
