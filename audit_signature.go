package zensframework

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AuditSignature gera assinaturas para operações de auditoria
type AuditSignature struct {
	secretKey string
}

// NewAuditSignature cria uma nova instância do gerador de assinaturas
func NewAuditSignature(secretKey string) *AuditSignature {
	return &AuditSignature{
		secretKey: secretKey,
	}
}

// GenerateOperationSignature gera uma assinatura para uma operação de auditoria
func (as *AuditSignature) GenerateOperationSignature(
	operation string,
	collectionName string,
	documentID string,
	before interface{},
	after interface{},
	userID string,
	timestamp time.Time,
) (string, error) {
	// Cria estrutura para assinatura
	signatureData := map[string]interface{}{
		"operation":  operation,
		"collection": collectionName,
		"documentId": documentID,
		"before":     before,
		"after":      after,
		"userId":     userID,
		"timestamp":  timestamp.Unix(),
		"secretKey":  as.secretKey,
	}

	// Serializa para JSON de forma determinística
	jsonData, err := json.Marshal(signatureData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature data: %w", err)
	}

	// Gera hash SHA256
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:]), nil
}

// VerifyOperationSignature verifica se uma assinatura é válida
func (as *AuditSignature) VerifyOperationSignature(
	operation string,
	collectionName string,
	documentID string,
	before interface{},
	after interface{},
	userID string,
	timestamp time.Time,
	signature string,
) bool {
	// Gera assinatura esperada
	expectedSignature, err := as.GenerateOperationSignature(
		operation, collectionName, documentID, before, after, userID, timestamp,
	)
	if err != nil {
		return false
	}

	// Compara assinaturas
	return expectedSignature == signature
}

// AuditRecord representa um registro de auditoria com assinatura
type AuditRecord struct {
	ID             string      `bson:"_id" json:"id"`
	Operation      string      `bson:"operation" json:"operation"`
	CollectionName string      `bson:"collectionName" json:"collectionName"`
	DocumentID     string      `bson:"documentId" json:"documentId"`
	Before         interface{} `bson:"before,omitempty" json:"before,omitempty"`
	After          interface{} `bson:"after,omitempty" json:"after,omitempty"`
	UserID         string      `bson:"userId" json:"userId"`
	Timestamp      time.Time   `bson:"timestamp" json:"timestamp"`
	Signature      string      `bson:"signature" json:"signature"`
	TenantID       string      `bson:"tenantId,omitempty" json:"tenantId,omitempty"`
}

// RegisterAuditSignature registra o gerador de assinaturas no framework
func (zsf *ZSFramework) RegisterAuditSignature(secretKey string) {
	err := zsf.ioc.Provide(func() *AuditSignature {
		return NewAuditSignature(secretKey)
	})
	if err != nil {
		panic(err)
	}
}
