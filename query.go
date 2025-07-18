package zensegur

import (
	"context"
	"errors"
)

type Query[T any] struct {
	repo    *MongoRepository[T]
	filters map[string]interface{}
	limit   int64
	skip    int64
	sort    map[string]int
}

func (r *MongoRepository[T]) Where(field string, op string, value interface{}) *Query[T] {
	q := &Query[T]{
		repo:    r,
		filters: make(map[string]interface{}),
	}
	
	switch op {
	case "==":
		q.filters[field] = value
	case "!=":
		q.filters[field] = map[string]interface{}{"$ne": value}
	case ">":
		q.filters[field] = map[string]interface{}{"$gt": value}
	case ">=":
		q.filters[field] = map[string]interface{}{"$gte": value}
	case "<":
		q.filters[field] = map[string]interface{}{"$lt": value}
	case "<=":
		q.filters[field] = map[string]interface{}{"$lte": value}
	case "in":
		q.filters[field] = map[string]interface{}{"$in": value}
	case "not-in":
		q.filters[field] = map[string]interface{}{"$nin": value}
	case "array-contains":
		q.filters[field] = map[string]interface{}{"$elemMatch": value}
	default:
		q.filters[field] = value
	}
	
	return q
}

func (q *Query[T]) Where(field string, op string, value interface{}) *Query[T] {
	switch op {
	case "==":
		q.filters[field] = value
	case "!=":
		q.filters[field] = map[string]interface{}{"$ne": value}
	case ">":
		q.filters[field] = map[string]interface{}{"$gt": value}
	case ">=":
		q.filters[field] = map[string]interface{}{"$gte": value}
	case "<":
		q.filters[field] = map[string]interface{}{"$lt": value}
	case "<=":
		q.filters[field] = map[string]interface{}{"$lte": value}
	case "in":
		q.filters[field] = map[string]interface{}{"$in": value}
	case "not-in":
		q.filters[field] = map[string]interface{}{"$nin": value}
	case "array-contains":
		q.filters[field] = map[string]interface{}{"$elemMatch": value}
	default:
		q.filters[field] = value
	}
	
	return q
}

func (q *Query[T]) Limit(limit int64) *Query[T] {
	q.limit = limit
	return q
}

func (q *Query[T]) Skip(skip int64) *Query[T] {
	q.skip = skip
	return q
}

func (q *Query[T]) OrderBy(field string, desc bool) *Query[T] {
	if q.sort == nil {
		q.sort = make(map[string]int)
	}
	
	if desc {
		q.sort[field] = -1
	} else {
		q.sort[field] = 1
	}
	
	return q
}

func (q *Query[T]) Execute() ([]T, error) {
	ctx := context.Background()
	
	if q.repo.tenantID != "" {
		q.filters["tenant_id"] = q.repo.tenantID
	}
	
	if _, hasActiveFilter := q.filters["active"]; !hasActiveFilter {
		q.filters["active"] = true
	}
	
	results := q.repo.GetAll(ctx, q.filters)
	if results == nil {
		return nil, errors.New("erro ao executar consulta")
	}
	
	return *results, nil
}

func (q *Query[T]) First(result *T) error {
	ctx := context.Background()
	
	if q.repo.tenantID != "" {
		q.filters["tenant_id"] = q.repo.tenantID
	}
	
	if _, hasActiveFilter := q.filters["active"]; !hasActiveFilter {
		q.filters["active"] = true
	}
	
	found := q.repo.GetFirst(ctx, q.filters)
	if found == nil {
		return errors.New("not found")
	}
	
	*result = *found
	return nil
}