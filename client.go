package zensegur

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Client struct {
	mongoClient *mongo.Client
	database    string
	tenantID    string
	userID      string
	username    string
	cache       *Cache
	auditLog    bool
}

func NewClient(ctx context.Context, uri string, database string) (*Client, error) {
	clientOptions := options.Client().ApplyURI(uri)
	
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	mongoClient, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, err
	}
	
	err = mongoClient.Ping(ctx, nil)
	if err != nil {
		return nil, err
	}
	
	return &Client{
		mongoClient: mongoClient,
		database:    database,
		auditLog:    false,
	}, nil
}

func (c *Client) Close() error {
	return c.mongoClient.Disconnect(context.Background())
}

func (c *Client) WithTenant(tenantID string) *Client {
	clone := *c
	clone.tenantID = tenantID
	return &clone
}

func (c *Client) WithAuthor(userID string, username string) *Client {
	clone := *c
	clone.userID = userID
	clone.username = username
	return &clone
}

func (c *Client) WithAudit(enabled bool) *Client {
	clone := *c
	clone.auditLog = enabled
	return &clone
}

func (c *Client) WithCache(cache *Cache) *Client {
	clone := *c
	clone.cache = cache
	return &clone
}

func (c *Client) Repository(collection string) *MongoRepository[map[string]interface{}] {
	repo := NewMongoRepository[map[string]interface{}](c.mongoClient, c.database, collection)
	
	if c.tenantID != "" {
		repo = repo.WithTenant(c.tenantID)
	}
	
	if c.userID != "" {
		repo = repo.WithAuthor(c.userID, c.username)
	}
	
	if c.auditLog {
		repo = repo.WithAudit(true)
	}
	
	if c.cache != nil {
		repo = repo.WithCache(c.cache)
	}
	
	return repo
}

func (c *Client) RepositoryTyped(collection string) interface{} {
	return c.Repository(collection)
}