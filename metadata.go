package zensegur

import (
	"context"
	"time"
)

type CreatedBy struct {
	Date       time.Time `firestore:"date"`
	AuthorID   string    `firestore:"author_id"`
	AuthorName string    `firestore:"author_name"`
}

type UpdatedBy struct {
	Date       time.Time `firestore:"date"`
	AuthorID   string    `firestore:"author_id"`
	AuthorName string    `firestore:"author_name"`
}

type BaseDocument struct {
	Created   CreatedBy  `firestore:"created"`
	Updated   UpdatedBy  `firestore:"updated"`
	DeletedAt *time.Time `firestore:"deleted_at,omitempty"`
	Active    bool       `firestore:"active"`
}

func (r *Repository) WithAuthor(authorID, authorName string) *Repository {
	return &Repository{
		client:     r.client,
		collection: r.collection,
		ctx:        context.WithValue(context.WithValue(r.ctx, "author_id", authorID), "author_name", authorName),
	}
}

func (r *Repository) addMetadata(data map[string]interface{}, isUpdate bool) {
	authorID, _ := r.ctx.Value("author_id").(string)
	authorName, _ := r.ctx.Value("author_name").(string)
	now := time.Now()

	if !isUpdate {
		data["created"] = CreatedBy{
			Date:       now,
			AuthorID:   authorID,
			AuthorName: authorName,
		}
		data["active"] = true
	}

	data["updated"] = UpdatedBy{
		Date:       now,
		AuthorID:   authorID,
		AuthorName: authorName,
	}
}
