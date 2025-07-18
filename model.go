package zensegur

import (
	"time"
)

type BaseDocument struct {
	CreatedAt  time.Time  `bson:"created_at" json:"created_at"`
	UpdatedAt  time.Time  `bson:"updated_at" json:"updated_at"`
	DeletedAt  *time.Time `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
	Active     bool       `bson:"active" json:"active"`
	CreatedBy  string     `bson:"created_by,omitempty" json:"created_by,omitempty"`
	UpdatedBy  string     `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}

func (b *BaseDocument) SetCreatedAt(t time.Time) { b.CreatedAt = t }
func (b *BaseDocument) SetUpdatedAt(t time.Time) { b.UpdatedAt = t }
func (b *BaseDocument) SetActive(active bool)    { b.Active = active }
func (b *BaseDocument) SetCreatedBy(userID string) { b.CreatedBy = userID }
func (b *BaseDocument) SetUpdatedBy(userID string) { b.UpdatedBy = userID }

type Documentable interface {
	Timestampable
	Activable
	Authorable
}

func ApplyMetadata[T any](doc T, isUpdate bool, userID string) T {
	now := time.Now()
	
	if ts, ok := any(doc).(Timestampable); ok {
		if !isUpdate {
			ts.SetCreatedAt(now)
		}
		ts.SetUpdatedAt(now)
	}
	
	if act, ok := any(doc).(Activable); ok && !isUpdate {
		act.SetActive(true)
	}
	
	if auth, ok := any(doc).(Authorable); ok {
		if !isUpdate {
			auth.SetCreatedBy(userID)
		} else {
			auth.SetUpdatedBy(userID)
		}
	}
	
	return doc
}