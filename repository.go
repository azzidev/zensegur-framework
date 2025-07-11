package zensegur

import (
	"context"
	"errors"
	"reflect"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
)

type Filter struct {
	Field string
	Op    string
	Value interface{}
}

type Repository struct {
	client     *firestore.Client
	collection string
	ctx        context.Context
}

type Query struct {
	repo    *Repository
	filters []Filter
	limit   int
	offset  int
	orderBy string
	desc    bool
}

func NewRepository(client *firestore.Client, collection string) *Repository {
	return &Repository{
		client:     client,
		collection: collection,
		ctx:        context.Background(),
	}
}

func (r *Repository) GetFirst(result interface{}, field, value string) error {
	iter := r.client.Collection(r.collection).Where(field, "==", value).Limit(1).Documents(r.ctx)
	doc, err := iter.Next()
	if err != nil {
		if err == iterator.Done {
			return errors.New("not found")
		}
		return err
	}
	return doc.DataTo(result)
}

func (r *Repository) GetByID(id string, result interface{}) error {
	doc, err := r.client.Collection(r.collection).Doc(id).Get(r.ctx)
	if err != nil {
		return err
	}
	return doc.DataTo(result)
}

func (r *Repository) GetAll(results interface{}) error {
	iter := r.client.Collection(r.collection).Documents(r.ctx)
	return r.populateSlice(iter, results)
}

func (r *Repository) GetAllSkipTake(results interface{}, skip, take int) error {
	iter := r.client.Collection(r.collection).Offset(skip).Limit(take).Documents(r.ctx)
	return r.populateSlice(iter, results)
}

func (r *Repository) Where(field, op string, value interface{}) *Query {
	return &Query{
		repo:    r,
		filters: []Filter{{Field: field, Op: op, Value: value}},
	}
}

func (r *Repository) Query() *Query {
	return &Query{repo: r}
}

func (q *Query) Where(field, op string, value interface{}) *Query {
	q.filters = append(q.filters, Filter{Field: field, Op: op, Value: value})
	return q
}

func (q *Query) Limit(limit int) *Query {
	q.limit = limit
	return q
}

func (q *Query) Skip(offset int) *Query {
	q.offset = offset
	return q
}

func (q *Query) OrderBy(field string, desc bool) *Query {
	q.orderBy = field
	q.desc = desc
	return q
}

func (q *Query) Execute(results interface{}) error {
	query := q.repo.client.Collection(q.repo.collection).Query

	for _, filter := range q.filters {
		query = query.Where(filter.Field, filter.Op, filter.Value)
	}

	if q.orderBy != "" {
		dir := firestore.Asc
		if q.desc {
			dir = firestore.Desc
		}
		query = query.OrderBy(q.orderBy, dir)
	}

	if q.offset > 0 {
		query = query.Offset(q.offset)
	}

	if q.limit > 0 {
		query = query.Limit(q.limit)
	}

	iter := query.Documents(q.repo.ctx)
	return q.repo.populateSlice(iter, results)
}

func (q *Query) First(result interface{}) error {
	query := q.repo.client.Collection(q.repo.collection).Query

	for _, filter := range q.filters {
		query = query.Where(filter.Field, filter.Op, filter.Value)
	}

	if q.orderBy != "" {
		dir := firestore.Asc
		if q.desc {
			dir = firestore.Desc
		}
		query = query.OrderBy(q.orderBy, dir)
	}

	iter := query.Limit(1).Documents(q.repo.ctx)
	doc, err := iter.Next()
	if err != nil {
		if err == iterator.Done {
			return errors.New("not found")
		}
		return err
	}
	return doc.DataTo(result)
}

func (r *Repository) Create(data interface{}) (string, error) {
	dataMap := r.toMap(data)
	r.addMetadata(dataMap, false)

	docRef, _, err := r.client.Collection(r.collection).Add(r.ctx, dataMap)
	if err != nil {
		return "", err
	}
	return docRef.ID, nil
}

func (r *Repository) CreateWithID(id string, data interface{}) error {
	dataMap := r.toMap(data)
	r.addMetadata(dataMap, false)

	_, err := r.client.Collection(r.collection).Doc(id).Set(r.ctx, dataMap)
	return err
}

func (r *Repository) Update(id string, data interface{}) error {
	dataMap := r.toMap(data)
	r.addMetadata(dataMap, true)

	_, err := r.client.Collection(r.collection).Doc(id).Set(r.ctx, dataMap, firestore.MergeAll)
	return err
}

func (r *Repository) UpdateFields(id string, fields map[string]interface{}) error {
	r.addMetadata(fields, true)

	updates := make([]firestore.Update, 0, len(fields))
	for k, v := range fields {
		updates = append(updates, firestore.Update{Path: k, Value: v})
	}
	_, err := r.client.Collection(r.collection).Doc(id).Update(r.ctx, updates)
	return err
}

func (r *Repository) Delete(id string) error {
	return r.SoftDelete(id)
}

func (r *Repository) SoftDelete(id string) error {
	fields := map[string]interface{}{
		"deleted_at": time.Now(),
		"active":     false,
	}
	r.addMetadata(fields, true)

	updates := make([]firestore.Update, 0, len(fields))
	for k, v := range fields {
		updates = append(updates, firestore.Update{Path: k, Value: v})
	}
	_, err := r.client.Collection(r.collection).Doc(id).Update(r.ctx, updates)
	return err
}

func (r *Repository) Count() (int, error) {
	iter := r.client.Collection(r.collection).Documents(r.ctx)
	count := 0
	for {
		_, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func (r *Repository) Exists(field, value string) (bool, error) {
	iter := r.client.Collection(r.collection).Where(field, "==", value).Limit(1).Documents(r.ctx)
	_, err := iter.Next()
	if err == iterator.Done {
		return false, nil
	}
	return err == nil, err
}

func (r *Repository) RunTransaction(fn func(context.Context, *firestore.Transaction) error) error {
	return r.client.RunTransaction(r.ctx, fn)
}

func (r *Repository) NewBatch() *firestore.WriteBatch {
	return r.client.Batch()
}

func (r *Repository) populateSlice(iter *firestore.DocumentIterator, results interface{}) error {
	v := reflect.ValueOf(results)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Slice {
		return errors.New("results must be a pointer to slice")
	}

	slice := v.Elem()
	elemType := slice.Type().Elem()

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}

		elem := reflect.New(elemType).Interface()
		if err := doc.DataTo(elem); err != nil {
			return err
		}

		slice.Set(reflect.Append(slice, reflect.ValueOf(elem).Elem()))
	}

	return nil
}

func (r *Repository) toMap(data interface{}) map[string]interface{} {
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	result := make(map[string]interface{})
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		tag := fieldType.Tag.Get("firestore")
		if tag == "" {
			tag = fieldType.Name
		}

		result[tag] = field.Interface()
	}

	return result
}
