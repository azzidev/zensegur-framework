package zensegur

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DataList[T any] struct {
	Items      []T   `json:"items"`
	TotalCount int64 `json:"totalCount"`
}

type MongoRepository[T any] struct {
	client     *mongo.Client
	database   *mongo.Database
	collection *mongo.Collection
	tenantID   string
	userID     string
	username   string
	cache      *Cache
	auditLog   bool
}

func NewMongoRepository[T any](client *mongo.Client, database string, collection string) *MongoRepository[T] {
	return &MongoRepository[T]{
		client:     client,
		database:   client.Database(database),
		collection: client.Database(database).Collection(collection),
		auditLog:   false,
	}
}

func (r *MongoRepository[T]) WithTenant(tenantID string) *MongoRepository[T] {
	clone := *r
	clone.tenantID = tenantID
	if tenantID != "" {
		clone.collection = r.database.Collection(tenantID + "_" + r.collection.Name())
	}
	return &clone
}

func (r *MongoRepository[T]) WithCache(cache *Cache) *MongoRepository[T] {
	clone := *r
	clone.cache = cache
	return &clone
}

func (r *MongoRepository[T]) ChangeCollection(collectionName string) {
	r.collection = r.database.Collection(collectionName)
}

func (r *MongoRepository[T]) GetAll(
	ctx context.Context,
	filter map[string]interface{},
	optsFind ...*options.FindOptions,
) *[]T {
	if r.cache != nil {
		cacheKey := r.getCacheKey(fmt.Sprintf("all:%v", filter))
		if cached := r.cache.Get(cacheKey); cached != nil {
			if results, ok := cached.(*[]T); ok {
				return results
			}
		}
	}

	if r.tenantID != "" {
		filter["tenant_id"] = r.tenantID
	}

	if _, hasActiveFilter := filter["active"]; !hasActiveFilter {
		filter["active"] = true
	}
	var results []T
	cursor, err := r.collection.Find(ctx, filter, optsFind...)
	if err != nil {
		return &results
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &results); err != nil {
		return &results
	}

	if r.cache != nil {
		cacheKey := r.getCacheKey(fmt.Sprintf("all:%v", filter))
		r.cache.Set(cacheKey, &results)
	}

	return &results
}

func (r *MongoRepository[T]) GetAllSkipTake(
	ctx context.Context,
	filter map[string]interface{},
	skip int64,
	take int64,
	optsFind ...*options.FindOptions,
) *DataList[T] {
	var results []T
	findOptions := options.Find().SetSkip(skip).SetLimit(take)
	if len(optsFind) > 0 {
		if optsFind[0].Sort != nil {
			findOptions.SetSort(optsFind[0].Sort)
		}
	}

	cursor, err := r.collection.Find(ctx, filter, findOptions)
	if err != nil {
		return &DataList[T]{Items: results, TotalCount: 0}
	}
	defer cursor.Close(ctx)

	if err := cursor.All(ctx, &results); err != nil {
		return &DataList[T]{Items: results, TotalCount: 0}
	}

	count := r.Count(ctx, filter)
	return &DataList[T]{Items: results, TotalCount: count}
}

func (r *MongoRepository[T]) GetFirst(
	ctx context.Context,
	filter map[string]interface{},
) *T {
	if r.cache != nil {
		cacheKey := r.getCacheKey(fmt.Sprintf("first:%v", filter))
		if cached := r.cache.Get(cacheKey); cached != nil {
			if result, ok := cached.(*T); ok {
				return result
			}
		}
	}

	if r.tenantID != "" {
		filter["tenant_id"] = r.tenantID
	}

	if _, hasActiveFilter := filter["active"]; !hasActiveFilter {
		filter["active"] = true
	}
	var result T
	err := r.collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		return nil
	}

	if r.cache != nil {
		cacheKey := r.getCacheKey(fmt.Sprintf("first:%v", filter))
		r.cache.Set(cacheKey, &result)
	}

	return &result
}

func (r *MongoRepository[T]) Insert(
	ctx context.Context,
	entity *T,
) error {
	*entity = ApplyMetadata(*entity, false, r.userID)

	res, err := r.collection.InsertOne(ctx, entity)
	if err != nil {
		return err
	}

	if r.auditLog {
		r.logAudit(ctx, "insert", res.InsertedID, nil, entity)
	}

	if r.cache != nil {
		r.cache.Delete(r.getCacheKey("*"))
	}

	return nil
}

type Timestampable interface {
	SetCreatedAt(time.Time)
	SetUpdatedAt(time.Time)
}

type Activable interface {
	SetActive(bool)
}

type Authorable interface {
	SetCreatedBy(string)
	SetUpdatedBy(string)
}

func (r *MongoRepository[T]) logAudit(ctx context.Context, action string, id interface{}, oldData, newData interface{}) {
	audit := map[string]interface{}{
		"collection":  r.collection.Name(),
		"document_id": id,
		"action":      action,
		"timestamp":   time.Now(),
		"user_id":     r.userID,
		"username":    r.username,
	}

	if oldData != nil {
		audit["old_data"] = oldData
	}

	if newData != nil {
		audit["new_data"] = newData
	}

	_, _ = r.database.Collection("audit_logs").InsertOne(ctx, audit)
}

func (r *MongoRepository[T]) getCacheKey(key string) string {
	prefix := r.collection.Name()
	if r.tenantID != "" {
		prefix = r.tenantID + "_" + prefix
	}
	return prefix + ":" + key
}

func (r *MongoRepository[T]) InsertAll(
	ctx context.Context,
	entities *[]T,
) error {
	var documents []interface{}
	for _, entity := range *entities {
		documents = append(documents, entity)
	}
	_, err := r.collection.InsertMany(ctx, documents)
	return err
}

func (r *MongoRepository[T]) Replace(
	ctx context.Context,
	filter map[string]interface{},
	entity *T,
) error {
	_, err := r.collection.ReplaceOne(ctx, filter, entity)
	return err
}

func (r *MongoRepository[T]) Update(
	ctx context.Context,
	filter map[string]interface{},
	fields interface{},
) error {
	var oldDocPtr *T
	if r.auditLog {
		oldDocPtr = r.GetFirst(ctx, filter)
	}

	fieldsMap, ok := fields.(map[string]interface{})
	if ok {
		fieldsMap["updated_at"] = time.Now()
		if r.userID != "" {
			fieldsMap["updated_by"] = r.userID
		}
		fields = fieldsMap
	}
	update := bson.M{"$set": fields}
	res, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if r.auditLog && res.MatchedCount > 0 {
		newDocPtr := r.GetFirst(ctx, filter)
		if newDocPtr != nil {
			r.logAudit(ctx, "update", filter, oldDocPtr, newDocPtr)
		}
	}
	if r.cache != nil {
		r.cache.Delete(r.getCacheKey("*"))
	}

	return nil
}

func (r *MongoRepository[T]) Delete(
	ctx context.Context,
	filter map[string]interface{},
) error {
	var oldDocPtr *T
	if r.auditLog {
		oldDocPtr = r.GetFirst(ctx, filter)
	}

	if r.tenantID != "" {
		filter["tenant_id"] = r.tenantID
	}

	deleteData := bson.M{
		"deleted_at": time.Now(),
		"active":     false,
		"updated_at": time.Now(),
	}

	if r.userID != "" {
		deleteData["updated_by"] = r.userID
	}
	update := bson.M{"$set": deleteData}
	res, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	if r.auditLog && res.MatchedCount > 0 && oldDocPtr != nil {
		r.logAudit(ctx, "delete", filter, oldDocPtr, nil)
	}
	if r.cache != nil {
		r.cache.Delete(r.getCacheKey("*"))
	}

	return nil
}

func (r *MongoRepository[T]) DeleteMany(
	ctx context.Context,
	filter map[string]interface{},
) error {
	update := bson.M{"$set": bson.M{"deleted_at": time.Now(), "active": false}}
	_, err := r.collection.UpdateMany(ctx, filter, update)
	return err
}

func (r *MongoRepository[T]) DeleteForce(
	ctx context.Context,
	filter map[string]interface{},
) error {
	_, err := r.collection.DeleteOne(ctx, filter)
	return err
}

func (r *MongoRepository[T]) DeleteManyForce(
	ctx context.Context,
	filter map[string]interface{},
) error {
	_, err := r.collection.DeleteMany(ctx, filter)
	return err
}

func (r *MongoRepository[T]) Aggregate(
	ctx context.Context,
	pipeline []interface{},
) (*mongo.Cursor, error) {
	return r.collection.Aggregate(ctx, pipeline)
}

func (r *MongoRepository[T]) DefaultAggregate(
	ctx context.Context,
	filter bson.A,
) (*mongo.Cursor, error) {
	return r.collection.Aggregate(ctx, filter)
}

func (r *MongoRepository[T]) Count(
	ctx context.Context,
	filter map[string]interface{},
	optsFind ...*options.CountOptions,
) int64 {
	count, err := r.collection.CountDocuments(ctx, filter, optsFind...)
	if err != nil {
		return 0
	}
	return count
}

func (r *MongoRepository[T]) GetLock(
	ctx context.Context,
	id interface{},
) (*T, error) {
	filter := bson.M{"_id": id, "locked": bson.M{"$ne": true}}
	update := bson.M{"$set": bson.M{"locked": true, "locked_at": time.Now()}}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)

	var result T
	err := r.collection.FindOneAndUpdate(ctx, filter, update, opts).Decode(&result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *MongoRepository[T]) Unlock(
	ctx context.Context,
	id interface{},
) error {
	filter := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{"locked": false, "locked_at": nil}}
	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

func (r *MongoRepository[T]) UpdateMany(
	ctx context.Context,
	filter map[string]interface{},
	fields interface{},
) error {
	update := bson.M{"$set": fields}
	_, err := r.collection.UpdateMany(ctx, filter, update)
	return err
}

func (r *MongoRepository[T]) PushMany(
	ctx context.Context,
	filter map[string]interface{},
	fields interface{},
) error {
	update := bson.M{"$push": fields}
	_, err := r.collection.UpdateMany(ctx, filter, update)
	return err
}

func (r *MongoRepository[T]) PullMany(
	ctx context.Context,
	filter map[string]interface{},
	fields interface{},
) error {
	update := bson.M{"$pull": fields}
	_, err := r.collection.UpdateMany(ctx, filter, update)
	return err
}

func (r *MongoRepository[T]) SetExpiredAfterInsert(ctx context.Context, seconds int32) error {
	indexModel := mongo.IndexModel{
		Keys:    bson.M{"created_at": 1},
		Options: options.Index().SetExpireAfterSeconds(seconds),
	}
	_, err := r.collection.Indexes().CreateOne(ctx, indexModel)
	return err
}

func (r *MongoRepository[T]) FindOneAndUpdate(
	ctx context.Context,
	filter map[string]interface{},
	fields map[string]interface{},
) (*T, error) {
	update := bson.M{"$set": fields}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)

	var result T
	err := r.collection.FindOneAndUpdate(ctx, filter, update, opts).Decode(&result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
