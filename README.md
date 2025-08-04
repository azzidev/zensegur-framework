# ZenSegur Framework

Core framework for ZenSegur applications with MongoDB integration, Google Pub/Sub messaging, and audit logging.

## Features

- MongoDB Repository Pattern
- Google Pub/Sub Integration
- MongoDB Audit Logging with Digital Signatures
- Telemetry and Monitoring
- Redis Cache Integration
- JWT Authentication with Token Revocation
- JWT Key Rotation Support (kid)
- CSRF Protection with Double Submit Cookie
- Rate Limiting
- Role-based Access Control (RBAC)
- Group-based Permission System
- Multi-tenant Group Management
- Token Blacklist with Redis

## Table of Contents

- [Installation](#installation)
- [Core Components](#core-components)
  - [ZSFramework](#zsframework)
  - [MongoDB Repository](#mongodb-repository)
  - [Google Pub/Sub](#google-pub-sub)
  - [Authentication & Authorization](#authentication--authorization)
  - [Token Blacklist & Revocation](#token-blacklist--revocation)
  - [JWT Key Rotation](#jwt-key-rotation)
  - [CSRF Protection](#csrf-protection)
  - [Audit Logging with Signatures](#audit-logging-with-signatures)
  - [Group-based Permissions](#group-based-permissions)
  - [Redis Cache](#redis-cache)
  - [Telemetry](#telemetry)
- [API Reference](#api-reference)

## Installation

```bash
go get github.com/azzidev/zensegur-framework
```

## Core Components

### ZSFramework

The main framework container that orchestrates all components.

```go
// Initialize the framework
framework := zensframework.NewZSFramework()

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

### Audit Logging with Signatures

Automatic audit logging for MongoDB operations with digital signatures to prevent tampering.

```go
// Register audit signature generator
framework.RegisterAuditSignature("audit-secret-key")

// Enable audit logging in your configuration
v := viper.New()
v.SetDefault("audit.enabled", true)

// When creating your repository, audit logging is automatically enabled
repo := zensframework.NewMongoDbRepository[YourEntity](db, monitoring, v)

// All insert, update, and delete operations will be logged automatically with signatures

// Manual signature verification
framework.Invoke(func(auditSig *zensframework.AuditSignature) {
    // Generate signature for operation
    signature, err := auditSig.GenerateOperationSignature(
        "update", "users", "user-id", beforeData, afterData, "user-id", timestamp,
    )
    
    // Verify signature
    isValid := auditSig.VerifyOperationSignature(
        "update", "users", "user-id", beforeData, afterData, "user-id", timestamp, signature,
    )
})
```

### JWT Authentication

Utilities for JWT token generation, validation, and HttpOnly cookie management with enhanced security features.

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
    Issuer:         "zensegur-auth",  // Emissor para validação
    BcryptCost:     14,               // Fator de custo para hashing de senhas
}

// Register JWT helper
framework.RegisterJWTHelper(config)

// Register CSRF protection
framework.RegisterCSRFProtection(router)

// Register Rate Limiter (5 requests per minute by default)
framework.RegisterRateLimiter(router, DefaultRateLimiterConfig())

// Or with custom configuration
framework.RegisterRateLimiter(loginRouter, RateLimiterConfig{
    RequestsPerMinute: 3,  // 3 tentativas por minuto
    BurstSize:         3,
})

// Create middleware config with public paths
middlewareConfig := framework.CreateJWTMiddlewareConfig([]string{
    "/login",
    "/register",
    "/refresh",
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
    
    // Routes requiring specific roles (any of the listed roles)
    superAdmin := router.Group("/super-admin")
    superAdmin.Use(jwt.RequireRole("SUPER_ADMIN", "ADMIN"))
    
    // Routes requiring all specified roles
    restrictedAdmin := router.Group("/restricted-admin")
    restrictedAdmin.Use(jwt.RequireAllRoles("SUPER_ADMIN", "SECURITY_OFFICER"))
    
    // Routes requiring all specified permissions
    secureOperations := router.Group("/secure-operations")
    secureOperations.Use(jwt.RequireAllPermissions("users:write", "users:delete"))
})

// Custom claims validation function
func validateClaims(c *gin.Context, claims jwt.Claims) error {
    // You can implement your own validation logic here
    // For example, check if user has required permissions
    return nil
}

// Login handler example with HttpOnly cookies
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
        
        // Generate tokens
        accessToken, err := jwt.GenerateToken(claims, time.Hour)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }
        
        refreshClaims := jwt.MapClaims{
            "sub":        userId,
            "token_type": "refresh",
            "exp":        time.Now().Add(time.Hour * 24 * 7).Unix(),
        }
        refreshToken, _ := jwt.GenerateToken(refreshClaims, time.Hour * 24 * 7)
        
        // Set HttpOnly cookies
        jwt.SetAuthCookies(c, accessToken, refreshToken)
        
        // Return success response (without exposing tokens)
        c.JSON(http.StatusOK, gin.H{
            "success": true,
            "user": gin.H{
                "email": userEmail,
                "name": userName,
            },
        })
    }
}

// Password utilities
hashedPassword, _ := zensframework.HashPassword("user-password")
isValid := zensframework.CheckPassword("user-password", hashedPassword)
```

### Token Blacklist & Revocation

Redis-based token blacklist for secure token revocation.

```go
// Register token blacklist
framework.RegisterTokenBlacklist()

// Using token blacklist
framework.Invoke(func(blacklist *zensframework.TokenBlacklist) {
    // Revoke a specific token
    err := blacklist.RevokeToken(ctx, tokenString)
    
    // Check if token is revoked
    isRevoked, err := blacklist.IsTokenRevoked(ctx, tokenString)
    
    // Revoke all tokens for a user
    err := blacklist.RevokeAllUserTokens(ctx, userID)
    
    // Check if user tokens are revoked
    isRevoked, err := blacklist.IsUserTokensRevoked(ctx, userID, tokenIssuedAt)
})
```

### JWT Key Rotation

Support for multiple JWT keys with rotation capabilities.

```go
// Register JWT key manager
framework.RegisterJWTKeyManager("initial-secret", "key-001")

// Using key rotation
framework.Invoke(func(keyManager *zensframework.JWTKeyManager) {
    // Add new key
    keyManager.AddKey("key-002", "new-secret-key")
    
    // Set current key for new tokens
    err := keyManager.SetCurrentKey("key-002")
    
    // Remove old key (cannot remove current key)
    err := keyManager.RemoveKey("key-001")
})

// Using JWT helper with rotation
framework.Invoke(func(jwtHelper *zensframework.JWTHelperWithRotation) {
    // Generate token with current key
    token, err := jwtHelper.GenerateTokenWithRotation(claims, expiry)
    
    // Validate token (automatically uses correct key based on kid)
    err := jwtHelper.ValidateTokenWithRotation(tokenString, claims)
})
```

### CSRF Protection

Double Submit Cookie CSRF protection.

```go
// Register CSRF protection
framework.RegisterCSRFProtection(router)

// Get CSRF token endpoint (automatically registered)
// GET /csrf-token
// Response: {"token": "csrf-token-value"}

// Client usage:
// 1. Get CSRF token from /csrf-token endpoint
// 2. Include token in X-CSRF-Token header for non-safe methods
// 3. Token is also set as cookie automatically

// Manual CSRF token generation
framework.Invoke(func(c *gin.Context) {
    // Set CSRF token for current session
    zensframework.SetCSRFToken(c)
    
    // Generate new token
    token := zensframework.GenerateCSRFToken()
})
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

### ZSFramework

| Method | Description |
|--------|-------------|
| `NewZSFramework(opts ...ZSFrameworkOptions)` | Creates a new framework instance |
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
| `RegisterGroupRepository(constructor interface{})` | Registers a repository for groups |
| `RegisterUserGroupMappingRepository(constructor interface{})` | Registers a repository for user-group mappings |
| `RegisterGroupManager()` | Registers the group manager |
| `RegisterAuthEndpoints()` | Registers authentication endpoints |
| `RegisterTokenBlacklist()` | Registers token blacklist with Redis |
| `RegisterJWTKeyManager(initialKey, initialKid)` | Registers JWT key manager for rotation |
| `RegisterAuditSignature(secretKey)` | Registers audit signature generator |
| `RegisterRolesSignature(secretKey)` | Registers roles signature generator |
| `RegisterUserRolesHelper()` | Registers user roles helper |
| `RegisterRateLimiter(routerGroup, config)` | Registers rate limiting middleware |
| `RegisterCSRFProtection(routerGroup)` | Registers CSRF protection middleware |
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
| `HashPasswordWithCost(password, cost)` | Creates a bcrypt hash with custom cost factor |
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
| `RequireAllRoles(roles...)` | Creates a middleware that requires all specified roles |
| `RequireAllPermissions(permissions...)` | Creates a middleware that requires all specified permissions |

### Token Blacklist

| Method | Description |
|--------|-------------|
| `NewTokenBlacklist(redisClient)` | Creates a new token blacklist |
| `RevokeToken(ctx, tokenString)` | Revokes a specific token |
| `IsTokenRevoked(ctx, tokenString)` | Checks if a token is revoked |
| `RevokeAllUserTokens(ctx, userID)` | Revokes all tokens for a user |
| `IsUserTokensRevoked(ctx, userID, tokenIssuedAt)` | Checks if user tokens are revoked |

### JWT Key Rotation

| Method | Description |
|--------|-------------|
| `NewJWTKeyManager(initialKey, initialKid)` | Creates a new key manager |
| `AddKey(kid, secret)` | Adds a new key |
| `SetCurrentKey(kid)` | Sets the current key for new tokens |
| `GetCurrentKey()` | Returns the current key |
| `GetKey(kid)` | Returns a specific key |
| `RemoveKey(kid)` | Removes a key (except current) |
| `GenerateTokenWithRotation(claims, expiry)` | Generates token with current key |
| `ValidateTokenWithRotation(tokenString, claims)` | Validates token with appropriate key |

### Audit Signatures

| Method | Description |
|--------|-------------|
| `NewAuditSignature(secretKey)` | Creates a new audit signature generator |
| `GenerateOperationSignature(...)` | Generates signature for audit operation |
| `VerifyOperationSignature(...)` | Verifies an audit operation signature |

### Roles & Permissions Security

| Method | Description |
|--------|-------------|
| `NewRolesSignature(secretKey)` | Creates a new roles signature generator |
| `GenerateRolesSignature(userID, roles, timestamp)` | Generates signature for user roles |
| `VerifyRolesSignature(userID, roles, timestamp, signature)` | Verifies roles signature |
| `GeneratePermissionsSignature(userID, permissions, timestamp)` | Generates signature for user permissions |
| `VerifyPermissionsSignature(userID, permissions, timestamp, signature)` | Verifies permissions signature |
| `CreateSignedUserRoles(userID, roles, permissions, modifiedBy)` | Creates signed roles/permissions data |
| `ValidateUserRoles(data)` | Validates both roles and permissions signatures |

### User Roles Helper

| Method | Description |
|--------|-------------|
| `NewUserRolesHelper(rolesSignature, groupManager)` | Creates a new user roles helper |
| `GetUserRolesAndPermissions(ctx, userID, userRolesData)` | Gets validated roles and permissions for a user |
| `UpdateUserRoles(userID, newRoles, modifiedBy)` | Updates user roles with new signature |
| `UpdateUserPermissions(userID, newPermissions, modifiedBy)` | Updates user permissions with new signature |
| `CreateJWTClaims(ctx, userID, userName, userEmail, tenantID, userRolesData)` | Creates JWT claims with validated roles/permissions |

### Security Features

| Method | Description |
|--------|-------------|
| `CSRFMiddleware()` | Creates a middleware for CSRF protection |
| `SetCSRFToken(c)` | Sets a CSRF token for the current session |
| `GenerateCSRFToken()` | Generates a new CSRF token |
| `RateLimiterMiddleware(config)` | Creates a middleware for rate limiting |
| `DefaultRateLimiterConfig()` | Returns default rate limiter configuration |

### BSON Helpers

| Method | Description |
|--------|-------------|
| `MarshalWithRegistry(val)` | Marshals with custom registry |
| `UnmarshalWithRegistry(data, val)` | Unmarshals with custom registry |

### Group-based Permissions

The framework now supports a group-based permission system where permissions are fixed and defined by the system, but groups can be created with different combinations of permissions per tenant.

```go
// RegisterAuthEndpoints now creates repositories automatically!
// Just call this - no need to register repositories manually
framework.RegisterAuthEndpoints()

// This automatically creates:
// - zsf_groups collection with default repository
// - zsf_user_group_mappings collection with default repository  
// - GroupManager with the repositories
// - Auth endpoints: /api/auth/check-role, /api/auth/check-permission, /api/auth/permissions

// If you need custom repositories, register them BEFORE calling RegisterAuthEndpoints:
// framework.RegisterGroupRepository(NewCustomGroupRepository)
// framework.RegisterUserGroupMappingRepository(NewCustomMappingRepository)
// framework.RegisterAuthEndpoints()

// Example group repository implementation
type GroupRepository struct {
    repo zensframework.IRepository[zensframework.Group]
}

func NewGroupRepository(db *mongo.Database, monitoring *zensframework.Monitoring, v *viper.Viper) *GroupRepository {
    return &GroupRepository{
        repo: zensframework.NewMongoDbRepository[zensframework.Group](db, monitoring, v),
    }
}

// Example user-group mapping repository implementation
type UserGroupMappingRepository struct {
    repo zensframework.IRepository[zensframework.UserGroupMapping]
}

func NewUserGroupMappingRepository(db *mongo.Database, monitoring *zensframework.Monitoring, v *viper.Viper) *UserGroupMappingRepository {
    repo := zensframework.NewMongoDbRepository[zensframework.UserGroupMapping](db, monitoring, v)
    repo.ChangeCollection("zsf_user_group_mappings")
    return &UserGroupMappingRepository{
        repo: repo,
    }
}

// Using the group manager to check permissions
framework.Invoke(func(groupManager *zensframework.GroupManager) {
    // Check if user has all required permissions
    allowed, err := groupManager.CheckUserPermissions(ctx, userID, []string{"users:read", "users:write"})
    
    // Get all permissions for a user
    permissions, err := groupManager.GetUserPermissions(ctx, userID)
    
    // Add user to a group
    err := groupManager.AddUserToGroup(ctx, userID, groupID)
    
    // Remove user from a group
    err := groupManager.RemoveUserFromGroup(ctx, userID, groupID)
})

// Authentication endpoints for permission checking
// POST /api/auth/check-role - Check if user has all specified roles
// POST /api/auth/check-permission - Check if user has all specified permissions
// GET /api/auth/permissions - Get all permissions for the current user

// Example request to check roles
// POST /api/auth/check-role
// {"roles": ["ADMIN", "MANAGER"]}

// Example response
// {"allowed": true, "message": "User has all required roles"}

// Example permissions response (GET /api/auth/permissions)
// ✅ OTIMIZADO: Agora lê do JWT em vez de consultar o banco
// {
//   "roles": ["ADMIN", "USER"],
//   "permissions": [
//     "users:ler-basico",
//     "users:editar-dados",
//     "propostas:ler-valor",
//     "propostas:editar-prazo"
//   ]
// }

// Permission naming pattern: [domínio]:[ação]-[escopo]
// Examples:
// - propostas:ler-basico
// - propostas:ler-valor  
// - propostas:editar-valor
// - propostas:editar-prazo
// - users:criar-admin
// - users:listar-todos

// ✅ PERFORMANCE OPTIMIZATION:
// - Permissions são buscadas dos grupos APENAS na geração do token
// - Endpoints /api/auth/check-permission e /api/auth/permissions lêem do JWT
// - Elimina consultas ao banco em cada verificação de permissão
// - Mantém compatibilidade total com código existente

// Secure Roles & Permissions System
// Register roles signature system
framework.RegisterRolesSignature("your-roles-secret-key")
framework.RegisterUserRolesHelper()

// Using secure roles system
framework.Invoke(func(userRolesHelper *zensframework.UserRolesHelper) {
    // Update user roles securely
    userRolesData, err := userRolesHelper.UpdateUserRoles(
        userID, 
        []string{"ADMIN", "USER"}, 
        "admin-user-id",
    )
    
    // Create JWT claims with validated roles/permissions
    claims, err := userRolesHelper.CreateJWTClaims(
        ctx, userID, userName, userEmail, tenantID, userRolesData,
    )
    
    // Generate JWT token
    token, err := jwtHelper.GenerateToken(claims, time.Hour)
})

// Security Features:
// - Roles: MASTER, ADMIN, USER, EXTERNAL (fixed list)
// - Digital signatures prevent tampering in MongoDB
// - Invalid signatures fallback to "USER" role
// - Permissions combine direct + group permissions
// - HMAC SHA256 with secret key only in code
```