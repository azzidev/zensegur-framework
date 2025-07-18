package zensegur

import (
	"time"
)

type CreatedBy struct {
	Date       time.Time `bson:"date" json:"date"`
	AuthorID   string    `bson:"author_id" json:"author_id"`
	AuthorName string    `bson:"author_name" json:"author_name"`
}

type UpdatedBy struct {
	Date       time.Time `bson:"date" json:"date"`
	AuthorID   string    `bson:"author_id" json:"author_id"`
	AuthorName string    `bson:"author_name" json:"author_name"`
}

func (r *MongoRepository[T]) WithAuthor(userID string, username string) *MongoRepository[T] {
	clone := *r
	clone.userID = userID
	clone.username = username
	return &clone
}

func (r *MongoRepository[T]) addMetadataLegacy(data map[string]interface{}, isUpdate bool) {
	now := time.Now()

	if !isUpdate {
		data["created_at"] = now
		data["active"] = true
		if r.userID != "" {
			data["created_by"] = r.userID
		}
		if r.tenantID != "" {
			data["tenant_id"] = r.tenantID
		}
	}
	data["updated_at"] = now
	if r.userID != "" && isUpdate {
		data["updated_by"] = r.userID
	}
}
