# ZenSegur Framework

Core framework for ZenSegur applications with MongoDB integration, Google Pub/Sub messaging, and audit logging.

## Features

- MongoDB Repository Pattern
- Google Pub/Sub Integration
- MongoDB Audit Logging
- Telemetry and Monitoring
- Redis Cache Integration
- JWT Authentication Utilities
- Role-based Access Control (RBAC)
- Permission-based Security

## Table of Contents

- [Installation](#installation)
- [Core Components](#core-components)
  - [GoFramework](#goframework)
  - [MongoDB Repository](#mongodb-repository)
  - [Google Pub/Sub](#google-pub-sub)
  - [Authentication & Authorization](#authentication--authorization)
  - [Audit Logging](#audit-logging)
  - [Redis Cache](#redis-cache)
  - [Telemetry](#telemetry)
- [API Reference](#api-reference)

## Installation

```bash
go get github.com/azzidev/zensegur-framework
```

## Core Components

### GoFramework

The main framework container that orchestrates all components.

```go
// Initialize the framework
framework := zensframework.NewGoFramework()

// Configure CORS (default is already secure)
framework.ConfigureCORS([]string{"https://zensegur.com.br", "https://*.zensegur.com.br"}, true)

// Register MongoDB
framework.RegisterDbMongo("mongodb://localhost:27017", "user", "password", "database", false)

// Register PubSub
framework.RegisterPubSub("your-google-cloud-project-id")

// Register Redis
framework.RegisterRedis("localhost:6379", "", "0")

// Register repositories
framework.RegisterRepository(NewUserRepository)

// Register application services
framework.RegisterApplication(NewUserService)

// Register controllers
framework.RegisterController(NewUserController)

// Start the server
framework.Start()
```

### MongoDB Repository

Generic repository pattern for MongoDB with built-in audit logging.

```go
// Define your entity
type User struct {
    ID       uuid.UUID `bson:"_id"`
    Name     string    `bson:"name"`
    Email    string    `bson:"email"`
    Active   bool      `bson:"active"`
}

// Create repository
repo := zensframework.NewMongoDbRepository[User](db, monitoring, viper)

// Use repository methods
user := &User{
    ID:     uuid.New(),
    Name:   "John Doe",
    Email:  "john@example.com",
    Active: true,
}

// Insert
err := repo.Insert(ctx, user)

// Get by ID
filter := map[string]interface{}{"_id": id}
user := repo.GetFirst(ctx, filter)

// Update
err := repo.Update(ctx, filter, map[string]interface{}{
    "name": "Jane Doe",
})

// Delete (soft delete)
err := repo.Delete(ctx, filter)
```

### Google Pub/Sub

Messaging system using Google Pub/Sub.

```go
// Create a producer
producer, err := zensframework.NewPubSubProducer[YourMessageType](
    ctx, 
    "your-google-cloud-project-id", 
    "your-topic-name",
)
if err != nil {
    log.Fatalf("Failed to create producer: %v", err)
}
defer producer.Close()

// Publish a message
msg := &YourMessageType{...}
err = producer.Publish(ctx, msg)

// Create a consumer
messageHandler := func(ctx *zensframework.PubSubContext) {
    var msg YourMessageType
    err := json.Unmarshal(ctx.Msg.Data, &msg)
    if err != nil {
        ctx.Faulted = true
        return
    }
    
    // Process the message
    // ...
}

consumer, err := zensframework.NewPubSubConsumer(
    ctx,
    "your-google-cloud-project-id",
    "your-subscription-id",
    messageHandler,
)
if err != nil {
    log.Fatalf("Failed to create consumer: %v", err)
}
defer consumer.Close()

// Start consuming messages
go consumer.HandleFn()
```

### Audit Logging

Automatic audit logging for MongoDB operations.

```go
// Enable audit logging in your configuration
v := viper.New()
v.SetDefault("audit.enabled", true)

// When creating your repository, audit logging is automatically enabled
repo := zensframework.NewMongoDbRepository[YourEntity](db, monitoring, v)

// All insert, update, and delete operations will be logged automatically
```

### JWT Authentication

Utilities for JWT token generation, validation, and cookie management.

```go
// Configure JWT helper
config := &zensframework.JWTConfig{
    Secret:         "your-secret-key",
    AccessExpiry:   time.Hour,
    RefreshExpiry:  time.Hour * 24 * 7,
    CookieDomain:   "zensegur.com",
    CookieSecure:   true,
    CookieHTTPOnly: true,
    CookieSameSite: http.SameSiteStrictMode,
}

// Register JWT helper
framework.RegisterJWTHelper(config)

// Create middleware config with public paths
middlewareConfig := framework.CreateJWTMiddlewareConfig([]string{
    "/login",
    "/register",
    "/reset-password",
    "/health",
})

// In your controller setup
framework.Invoke(func(jwt *zensframework.JWTHelper, router *gin.RouterGroup) {
    // Apply authentication middleware with configuration
    router.Use(jwt.AuthMiddlewareWithConfig(middlewareConfig, validateClaims))
    
    // Public routes (automatically skipped from auth)
    router.POST("/login", handleLogin(jwt))
    router.POST("/register", handleRegister(jwt))
    
    // Routes requiring specific permissions
    admin := router.Group("/admin")
    admin.Use(jwt.RequirePermission("admin:access"))
    
    // Routes requiring specific roles
    superAdmin := router.Group("/super-admin")
    superAdmin.Use(jwt.RequireRole("SUPER_ADMIN"))
})

// Custom claims validation function
func validateClaims(c *gin.Context, claims jwt.Claims) error {
    // You can implement your own validation logic here
    // For example, check if user has required permissions
    return nil
}

// Login handler example
func handleLogin(jwt *zensframework.JWTHelper) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Authenticate user (implementation depends on your auth service)
        // ...
        
        // Create custom claims with roles and permissions
        claims := jwt.MapClaims{
            "sub":         userId,
            "name":        userName,
            "email":       userEmail,
            "tenant_id":   tenantId,
            "roles":       []string{"ADMIN", "USER"},
            "permissions": []string{"users:read", "users:write"},
            "exp":         time.Now().Add(time.Hour).Unix(),
        }
        
        // Generate token
        token, err := jwt.GenerateToken(claims, time.Hour)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }
        
        // Return token
        c.JSON(http.StatusOK, gin.H{"token": token})
    }
}

// Password utilities
hashedPassword, _ := zensframework.HashPassword("user-password")
isValid := zensframework.CheckPassword("user-password", hashedPassword)
```

### Redis Cache

Redis cache integration for high-performance caching.

```go
// Register Redis in the framework
framework.RegisterRedis("localhost:6379", "", "0")

// Create a cache implementation
type RedisCache struct {
    client *redis.Client
}

func NewRedisCache(client *redis.Client) zensframework.ICache {
    return &RedisCache{client: client}
}

// Implement cache methods
func (c *RedisCache) Get(key string, value interface{}) error {
    // Implementation
}

func (c *RedisCache) Set(key string, value interface{}, expiration time.Duration) error {
    // Implementation
}

// Register the cache
framework.RegisterCache(NewRedisCache)
```

### Telemetry

Built-in telemetry and monitoring.

```go
// Monitoring is automatically provided by the framework
framework.Invoke(func(monitoring *zensframework.Monitoring) {
    // Use monitoring
    correlation := uuid.New()
    mt := monitoring.Start(correlation, "service-name", zensframework.TracingTypeRepository)
    mt.AddContent(data)
    mt.AddStack(100, "operation-name")
    mt.End()
})
```

## API Reference

### GoFramework

| Method | Description |
|--------|-------------|
| `NewGoFramework(opts ...GoFrameworkOptions)` | Creates a new framework instance |
| `RegisterDbMongo(host, user, pass, database string, normalize bool)` | Registers MongoDB connection |
| `RegisterPubSub(projectID string, opts ...option.ClientOption)` | Registers Google Pub/Sub client |
| `RegisterRedis(address, password, db string)` | Registers Redis connection |
| `RegisterRepository(constructor interface{})` | Registers a repository |
| `RegisterApplication(application interface{})` | Registers an application service |
| `RegisterController(controller interface{})` | Registers a controller |
| `RegisterCache(constructor interface{})` | Registers a cache implementation |
| `RegisterPubSubProducer(producer interface{})` | Registers a PubSub producer |
| `RegisterPubSubConsumer(consumer interface{})` | Registers a PubSub consumer |
| `RegisterJWTHelper(config *JWTConfig)` | Registers the JWT helper |
| `ConfigureCORS(allowOrigins []string, allowCredentials bool)` | Configures CORS settings |
| `CreateJWTMiddlewareConfig(publicPaths []string)` | Creates a configuration for JWT middleware with public paths |
| `Start()` | Starts the HTTP server |
| `Invoke(function interface{})` | Invokes a function with dependency injection |
| `GetConfig(key string)` | Gets a configuration value |

### MongoDB Repository

| Method | Description |
|--------|-------------|
| `NewMongoDbRepository[T](db, monitoring, viper)` | Creates a new repository for type T |
| `ChangeCollection(collectionName string)` | Changes the collection name |
| `GetAll(ctx, filter, ...options)` | Gets all documents matching the filter |
| `GetAllSkipTake(ctx, filter, skip, take, ...options)` | Gets paginated documents |
| `GetFirst(ctx, filter)` | Gets the first document matching the filter |
| `Insert(ctx, entity)` | Inserts a new document |
| `InsertAll(ctx, entities)` | Inserts multiple documents |
| `Replace(ctx, filter, entity)` | Replaces a document |
| `Update(ctx, filter, fields)` | Updates document fields |
| `Delete(ctx, filter)` | Soft deletes a document |
| `DeleteMany(ctx, filter)` | Soft deletes multiple documents |
| `DeleteForce(ctx, filter)` | Hard deletes a document |
| `DeleteManyForce(ctx, filter)` | Hard deletes multiple documents |
| `Aggregate(ctx, pipeline)` | Performs an aggregation |
| `Count(ctx, filter, ...options)` | Counts documents matching the filter |
| `SetExpiredAfterInsert(ctx, seconds)` | Sets TTL index for documents |

### Google Pub/Sub

| Method | Description |
|--------|-------------|
| `NewPubSubProducer[T](ctx, projectID, topicName, ...options)` | Creates a new producer |
| `Publish(ctx, msgs)` | Publishes messages |
| `PublishWithAttributes(ctx, attributes, msgs)` | Publishes messages with attributes |
| `Close()` | Closes the producer |
| `NewPubSubConsumer(ctx, projectID, subscriptionID, handlerFunc, ...options)` | Creates a new consumer |
| `HandleFn()` | Starts consuming messages |
| `Close()` | Closes the consumer |

### Audit Logger

| Method | Description |
|--------|-------------|
| `NewAuditLogger(db, enabled)` | Creates a new audit logger |
| `LogInsert(ctx, collectionName, documentID, document)` | Logs an insert operation |
| `LogUpdate(ctx, collectionName, documentID, before, after)` | Logs an update operation |
| `LogDelete(ctx, collectionName, documentID, document, isSoftDelete)` | Logs a delete operation |
| `CreateAuditIndexes(ctx)` | Creates indexes for the audit collection |

### Monitoring

| Method | Description |
|--------|-------------|
| `NewMonitoring(v)` | Creates a new monitoring instance |
| `Start(correlation, sourceName, tracingType)` | Starts a monitoring trace |
| `AddContent(content)` | Adds content to the trace |
| `AddStack(skip, message)` | Adds stack information |
| `End()` | Ends the trace |

### Context Helpers

| Method | Description |
|--------|-------------|
| `GetContextHeader(ctx, keys...)` | Gets a header from the context |
| `ToContext(ctx)` | Converts to a standard context |
| `GetTenantByToken(ctx)` | Extracts tenant ID from JWT token |
| `helperContextHeaders(ctx, addfilter)` | Helper for context headers |

### JWT Authentication

| Method | Description |
|--------|-------------|
| `NewJWTHelper(config)` | Creates a new JWT helper |
| `HashPassword(password)` | Creates a bcrypt hash from a password |
| `CheckPassword(password, hash)` | Compares a password with a hash |
| `GenerateToken(claims, expiry)` | Generates a JWT token with the given claims |
| `ValidateToken(tokenString, claims)` | Validates a JWT token and returns the claims |
| `SetAuthCookies(c, accessToken, refreshToken)` | Sets authentication cookies |
| `ClearAuthCookies(c)` | Clears authentication cookies |
| `GetTokenFromRequest(c)` | Extracts token from request |
| `AuthMiddleware(validateFunc)` | Creates a middleware for JWT authentication |
| `AuthMiddlewareWithConfig(config, validateFunc)` | Creates a middleware for JWT authentication with configuration |
| `RequirePermission(permissions...)` | Creates a middleware that requires specific permissions |
| `RequireRole(roles...)` | Creates a middleware that requires specific roles |

### BSON Helpers

| Method | Description |
|--------|-------------|
| `MarshalWithRegistry(val)` | Marshals with custom registry |
| `UnmarshalWithRegistry(data, val)` | Unmarshals with custom registry |