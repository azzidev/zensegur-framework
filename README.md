# ZenSegur Framework

Framework principal para aplicações ZenSegur com integração MongoDB, mensageria Google Pub/Sub e auditoria.

## Funcionalidades

- Padrão Repository para MongoDB
- Integração Google Pub/Sub
- Auditoria MongoDB com Assinaturas Digitais
- Telemetria e Monitoramento
- Integração Cache Redis
- Autenticação JWT com Revogação de Tokens
- Proteção CSRF com Double Submit Cookie
- Rate Limiting
- Controle de Acesso Baseado em Roles (RBAC)
- Sistema de Permissões via JWT
- Gerenciamento Multi-tenant
- Blacklist de Tokens com Redis

## Índice

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

O container principal do framework que orquestra todos os componentes.

```go
// Inicializar o framework
framework := zensframework.NewZSFramework()

// Configurar CORS (padrão já é seguro)
framework.ConfigureCORS([]string{"https://zensegur.com.br", "https://*.zensegur.com.br"}, true)

// Registrar MongoDB
framework.RegisterDbMongo("mongodb://localhost:27017", "user", "password", "database", false)

// Registrar PubSub
framework.RegisterPubSub("your-google-cloud-project-id")

// Registrar Redis
framework.RegisterRedis("localhost:6379", "", "0")

// Registrar repositórios
framework.RegisterRepository(NewUserRepository)

// Registrar serviços de aplicação
framework.RegisterApplication(NewUserService)

// Registrar controladores
framework.RegisterController(NewUserController)

// Registrar endpoints de autenticação (apenas JWT decode)
framework.RegisterAuthEndpoints()

// Iniciar o servidor
framework.Start()
```

### MongoDB Repository

Padrão de repositório genérico para MongoDB com auditoria integrada.

```go
// Definir sua entidade
type User struct {
    ID       uuid.UUID `bson:"_id"`
    Name     string    `bson:"name"`
    Email    string    `bson:"email"`
    Active   bool      `bson:"active"`
}

// Criar repositório
repo := zensframework.NewMongoDbRepository[User](db, monitoring, viper)

// Usar métodos do repositório
user := &User{
    ID:     uuid.New(),
    Name:   "João Silva",
    Email:  "joao@exemplo.com",
    Active: true,
}

// Inserir
err := repo.Insert(ctx, user)

// Buscar por ID
filter := map[string]interface{}{"_id": id}
user := repo.GetFirst(ctx, filter)

// Atualizar
err := repo.Update(ctx, filter, map[string]interface{}{
    "name": "Maria Silva",
})

// Deletar (soft delete)
err := repo.Delete(ctx, filter)
```

### Google Pub/Sub

Sistema de mensageria usando Google Pub/Sub.

```go
// Criar um produtor
producer, err := zensframework.NewPubSubProducer[YourMessageType](
    ctx, 
    "your-google-cloud-project-id", 
    "your-topic-name",
)
if err != nil {
    log.Fatalf("Falha ao criar produtor: %v", err)
}
defer producer.Close()

// Publicar uma mensagem
msg := &YourMessageType{...}
err = producer.Publish(ctx, msg)

// Criar um consumidor
messageHandler := func(ctx *zensframework.PubSubContext) {
    var msg YourMessageType
    err := json.Unmarshal(ctx.Msg.Data, &msg)
    if err != nil {
        ctx.Faulted = true
        return
    }
    
    // Processar a mensagem
    // ...
}

consumer, err := zensframework.NewPubSubConsumer(
    ctx,
    "your-google-cloud-project-id",
    "your-subscription-id",
    messageHandler,
)
if err != nil {
    log.Fatalf("Falha ao criar consumidor: %v", err)
}
defer consumer.Close()

// Iniciar consumo de mensagens
go consumer.HandleFn()
```

### Audit Logging with Signatures

Auditoria automática para operações MongoDB com assinaturas digitais para prevenir adulteração.

```go
// Registrar gerador de assinatura de auditoria
framework.RegisterAuditSignature("audit-secret-key")

// Habilitar auditoria na sua configuração
v := viper.New()
v.SetDefault("audit.enabled", true)

// Ao criar seu repositório, auditoria é habilitada automaticamente
repo := zensframework.NewMongoDbRepository[YourEntity](db, monitoring, v)

// Todas as operações insert, update e delete serão logadas automaticamente com assinaturas

// Verificação manual de assinatura
framework.Invoke(func(auditSig *zensframework.AuditSignature) {
    // Gerar assinatura para operação
    signature, err := auditSig.GenerateOperationSignature(
        "update", "users", "user-id", beforeData, afterData, "user-id", timestamp,
    )
    
    // Verificar assinatura
    isValid := auditSig.VerifyOperationSignature(
        "update", "users", "user-id", beforeData, afterData, "user-id", timestamp, signature,
    )
})
```

### Authentication & Authorization

Sistema de autenticação JWT com gerenciamento de cookies HttpOnly e recursos de segurança avançados.

#### Endpoints do Framework (Apenas JWT Decode)

O framework fornece endpoints que leem apenas do JWT, sem consultas ao banco:

```go
// Registrar endpoints de autenticação
framework.RegisterAuthEndpoints()

// Endpoints disponíveis:
// POST /api/auth/check-role - Verifica se usuário tem roles específicas
// POST /api/auth/check-permission - Verifica se usuário tem permissões específicas  
// GET /api/auth/permissions - Retorna roles e permissions do usuário
```

#### Configuração JWT

```go
// Configurar JWT helper
config := &zensframework.JWTConfig{
    Secret:         "sua-chave-secreta",
    AccessExpiry:   time.Hour,
    RefreshExpiry:  time.Hour * 24 * 7,
    CookieDomain:   "zensegur.com",
    CookieSecure:   true,
    CookieHTTPOnly: true,
    CookieSameSite: http.SameSiteStrictMode,
    Issuer:         "zensegur-auth",  // Emissor para validação
    BcryptCost:     14,               // Fator de custo para hashing de senhas
}

// Registrar JWT helper
framework.RegisterJWTHelper(config)

// Registrar proteção CSRF
framework.RegisterCSRFProtection(router)

// Registrar Rate Limiter (5 requisições por minuto por padrão)
framework.RegisterRateLimiter(router, DefaultRateLimiterConfig())

// Ou com configuração customizada
framework.RegisterRateLimiter(loginRouter, RateLimiterConfig{
    RequestsPerMinute: 3,  // 3 tentativas por minuto
    BurstSize:         3,
})

// Criar configuração de middleware com paths públicos
middlewareConfig := framework.CreateJWTMiddlewareConfig([]string{
    "/login",
    "/register",
    "/refresh",
    "/health",
})

// Na configuração do seu controller
framework.Invoke(func(jwt *zensframework.JWTHelper, router *gin.RouterGroup) {
    // Aplicar middleware de autenticação com configuração
    router.Use(jwt.AuthMiddlewareWithConfig(middlewareConfig, validateClaims))
    
    // Rotas públicas (automaticamente ignoradas da autenticação)
    router.POST("/login", handleLogin(jwt))
    router.POST("/register", handleRegister(jwt))
    
    // Rotas que requerem permissões específicas
    admin := router.Group("/admin")
    admin.Use(jwt.RequirePermission("admin:access"))
    
    // Rotas que requerem roles específicas (qualquer uma das listadas)
    superAdmin := router.Group("/super-admin")
    superAdmin.Use(jwt.RequireRole("SUPER_ADMIN", "ADMIN"))
    
    // Rotas que requerem todas as roles especificadas
    restrictedAdmin := router.Group("/restricted-admin")
    restrictedAdmin.Use(jwt.RequireAllRoles("SUPER_ADMIN", "SECURITY_OFFICER"))
    
    // Rotas que requerem todas as permissões especificadas
    secureOperations := router.Group("/secure-operations")
    secureOperations.Use(jwt.RequireAllPermissions("users:write", "users:delete"))
})

// Função de validação de claims customizada
func validateClaims(c *gin.Context, claims jwt.Claims) error {
    // Você pode implementar sua própria lógica de validação aqui
    // Por exemplo, verificar se o usuário tem permissões necessárias
    return nil
}

// Exemplo de handler de login com cookies HttpOnly
func handleLogin(jwt *zensframework.JWTHelper) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Autenticar usuário (implementação depende do seu serviço de auth)
        // ...
        
        // Criar claims customizados com roles e permissões
        claims := jwt.MapClaims{
            "sub":         userId,
            "name":        userName,
            "email":       userEmail,
            "tenant_id":   tenantId,
            "roles":       []string{"ADMIN", "USER"},
            "permissions": []string{"users:read", "users:write"},
            "exp":         time.Now().Add(time.Hour).Unix(),
        }
        
        // Gerar tokens
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
        
        // Definir cookies HttpOnly
        jwt.SetAuthCookies(c, accessToken, refreshToken)
        
        // Retornar resposta de sucesso (sem expor tokens)
        c.JSON(http.StatusOK, gin.H{
            "success": true,
            "user": gin.H{
                "email": userEmail,
                "name": userName,
            },
        })
    }
}

// Utilitários de senha
hashedPassword, _ := zensframework.HashPassword("user-password")
isValid := zensframework.CheckPassword("user-password", hashedPassword)
```

### Token Blacklist & Revocation

Blacklist de tokens baseado em Redis para revogação segura de tokens.

```go
// Registrar blacklist de tokens
framework.RegisterTokenBlacklist()

// Usando blacklist de tokens
framework.Invoke(func(blacklist *zensframework.TokenBlacklist) {
    // Revogar um token específico
    err := blacklist.RevokeToken(ctx, tokenString)
    
    // Verificar se token foi revogado
    isRevoked, err := blacklist.IsTokenRevoked(ctx, tokenString)
    
    // Revogar todos os tokens de um usuário
    err := blacklist.RevokeAllUserTokens(ctx, userID)
    
    // Verificar se tokens do usuário foram revogados
    isRevoked, err := blacklist.IsUserTokensRevoked(ctx, userID, tokenIssuedAt)
})
```

### JWT Key Rotation

Suporte para múltiplas chaves JWT com capacidades de rotação.

```go
// Registrar gerenciador de chaves JWT
framework.RegisterJWTKeyManager("chave-inicial", "key-001")

// Usando rotação de chaves
framework.Invoke(func(keyManager *zensframework.JWTKeyManager) {
    // Adicionar nova chave
    keyManager.AddKey("key-002", "nova-chave-secreta")
    
    // Definir chave atual para novos tokens
    err := keyManager.SetCurrentKey("key-002")
    
    // Remover chave antiga (não pode remover chave atual)
    err := keyManager.RemoveKey("key-001")
})

// Usando JWT helper com rotação
framework.Invoke(func(jwtHelper *zensframework.JWTHelperWithRotation) {
    // Gerar token com chave atual
    token, err := jwtHelper.GenerateTokenWithRotation(claims, expiry)
    
    // Validar token (usa automaticamente a chave correta baseada no kid)
    err := jwtHelper.ValidateTokenWithRotation(tokenString, claims)
})
```

### CSRF Protection

Proteção CSRF com Double Submit Cookie.

```go
// Registrar proteção CSRF
framework.RegisterCSRFProtection(router)

// Endpoint para obter token CSRF (registrado automaticamente)
// GET /csrf-token
// Response: {"token": "csrf-token-value"}

// Uso no cliente:
// 1. Obter token CSRF do endpoint /csrf-token
// 2. Incluir token no header X-CSRF-Token para métodos não seguros
// 3. Token também é definido como cookie automaticamente

// Geração manual de token CSRF
framework.Invoke(func(c *gin.Context) {
    // Definir token CSRF para sessão atual
    zensframework.SetCSRFToken(c)
    
    // Gerar novo token
    token := zensframework.GenerateCSRFToken()
})
```

### Redis Cache

Integração Redis cache para cache de alta performance.

```go
// Registrar Redis no framework
framework.RegisterRedis("localhost:6379", "", "0")

// Criar implementação de cache
type RedisCache struct {
    client *redis.Client
}

func NewRedisCache(client *redis.Client) zensframework.ICache {
    return &RedisCache{client: client}
}

// Implementar métodos de cache
func (c *RedisCache) Get(key string, value interface{}) error {
    // Implementação
}

func (c *RedisCache) Set(key string, value interface{}, expiration time.Duration) error {
    // Implementação
}

// Registrar o cache
framework.RegisterCache(NewRedisCache)
```

### Telemetry

Telemetria e monitoramento integrados.

```go
// Monitoramento é fornecido automaticamente pelo framework
framework.Invoke(func(monitoring *zensframework.Monitoring) {
    // Usar monitoramento
    correlation := uuid.New()
    mt := monitoring.Start(correlation, "service-name", zensframework.TracingTypeRepository)
    mt.AddContent(data)
    mt.AddStack(100, "operation-name")
    mt.End()
})
```

## API Reference

### ZSFramework

| Método | Descrição |
|--------|-------------|
| `NewZSFramework(opts ...ZSFrameworkOptions)` | Cria uma nova instância do framework |
| `RegisterDbMongo(host, user, pass, database string, normalize bool)` | Registra conexão MongoDB |
| `RegisterPubSub(projectID string, opts ...option.ClientOption)` | Registra cliente Google Pub/Sub |
| `RegisterRedis(address, password, db string)` | Registra conexão Redis |
| `RegisterRepository(constructor interface{})` | Registra um repositório |
| `RegisterApplication(application interface{})` | Registra um serviço de aplicação |
| `RegisterController(controller interface{})` | Registra um controlador |
| `RegisterCache(constructor interface{})` | Registra implementação de cache |
| `RegisterPubSubProducer(producer interface{})` | Registra um produtor PubSub |
| `RegisterPubSubConsumer(consumer interface{})` | Registra um consumidor PubSub |
| `RegisterJWTHelper(config *JWTConfig)` | Registra o helper JWT |
| `RegisterAuthEndpoints()` | Registra endpoints de autenticação (JWT decode apenas) |
| `RegisterTokenBlacklist()` | Registra blacklist de tokens com Redis |
| `RegisterJWTKeyManager(initialKey, initialKid)` | Registra gerenciador de chaves JWT para rotação |
| `RegisterAuditSignature(secretKey)` | Registra gerador de assinatura de auditoria |
| `RegisterRolesSignature(secretKey)` | Registra gerador de assinatura de roles |
| `RegisterUserRolesHelper()` | Registra helper de roles de usuário |
| `RegisterRateLimiter(routerGroup, config)` | Registra middleware de rate limiting |
| `RegisterCSRFProtection(routerGroup)` | Registra middleware de proteção CSRF |
| `ConfigureCORS(allowOrigins []string, allowCredentials bool)` | Configura settings de CORS |
| `CreateJWTMiddlewareConfig(publicPaths []string)` | Cria configuração para middleware JWT com paths públicos |
| `Start()` | Inicia o servidor HTTP |
| `Invoke(function interface{})` | Invoca uma função com injeção de dependência |
| `GetConfig(key string)` | Obtém um valor de configuração |

### MongoDB Repository

| Método | Descrição |
|--------|-------------|
| `NewMongoDbRepository[T](db, monitoring, viper)` | Cria um novo repositório para o tipo T |
| `ChangeCollection(collectionName string)` | Altera o nome da coleção |
| `GetAll(ctx, filter, ...options)` | Obtém todos os documentos que correspondem ao filtro |
| `GetAllSkipTake(ctx, filter, skip, take, ...options)` | Obtém documentos paginados |
| `GetFirst(ctx, filter)` | Obtém o primeiro documento que corresponde ao filtro |
| `Insert(ctx, entity)` | Insere um novo documento |
| `InsertAll(ctx, entities)` | Insere múltiplos documentos |
| `Replace(ctx, filter, entity)` | Substitui um documento |
| `Update(ctx, filter, fields)` | Atualiza campos do documento |
| `Delete(ctx, filter)` | Deleta um documento (soft delete) |
| `DeleteMany(ctx, filter)` | Deleta múltiplos documentos (soft delete) |
| `DeleteForce(ctx, filter)` | Deleta um documento (hard delete) |
| `DeleteManyForce(ctx, filter)` | Deleta múltiplos documentos (hard delete) |
| `Aggregate(ctx, pipeline)` | Executa uma agregação |
| `Count(ctx, filter, ...options)` | Conta documentos que correspondem ao filtro |
| `SetExpiredAfterInsert(ctx, seconds)` | Define índice TTL para documentos |

### Google Pub/Sub

| Método | Descrição |
|--------|-------------|
| `NewPubSubProducer[T](ctx, projectID, topicName, ...options)` | Cria um novo produtor |
| `Publish(ctx, msgs)` | Publica mensagens |
| `PublishWithAttributes(ctx, attributes, msgs)` | Publica mensagens com atributos |
| `Close()` | Fecha o produtor |
| `NewPubSubConsumer(ctx, projectID, subscriptionID, handlerFunc, ...options)` | Cria um novo consumidor |
| `HandleFn()` | Inicia o consumo de mensagens |
| `Close()` | Fecha o consumidor |

### Audit Logger

| Método | Descrição |
|--------|-------------|
| `NewAuditLogger(db, enabled)` | Cria um novo logger de auditoria |
| `LogInsert(ctx, collectionName, documentID, document)` | Loga uma operação de inserção |
| `LogUpdate(ctx, collectionName, documentID, before, after)` | Loga uma operação de atualização |
| `LogDelete(ctx, collectionName, documentID, document, isSoftDelete)` | Loga uma operação de deleção |
| `CreateAuditIndexes(ctx)` | Cria índices para a coleção de auditoria |

### Monitoring

| Método | Descrição |
|--------|-------------|
| `NewMonitoring(v)` | Cria uma nova instância de monitoramento |
| `Start(correlation, sourceName, tracingType)` | Inicia um trace de monitoramento |
| `AddContent(content)` | Adiciona conteúdo ao trace |
| `AddStack(skip, message)` | Adiciona informações de stack |
| `End()` | Finaliza o trace |

### Context Helpers

| Método | Descrição |
|--------|-------------|
| `GetContextHeader(ctx, keys...)` | Obtém um header do contexto |
| `ToContext(ctx)` | Converte para um contexto padrão |
| `GetTenantByToken(ctx)` | Extrai tenant ID do token JWT |
| `helperContextHeaders(ctx, addfilter)` | Helper para headers de contexto |

### JWT Authentication

| Método | Descrição |
|--------|-------------|
| `NewJWTHelper(config)` | Cria um novo helper JWT |
| `HashPassword(password)` | Cria um hash bcrypt de uma senha |
| `HashPasswordWithCost(password, cost)` | Cria um hash bcrypt com fator de custo customizado |
| `CheckPassword(password, hash)` | Compara uma senha com um hash |
| `GenerateToken(claims, expiry)` | Gera um token JWT com os claims fornecidos |
| `ValidateToken(tokenString, claims)` | Valida um token JWT e retorna os claims |
| `SetAuthCookies(c, accessToken, refreshToken)` | Define cookies de autenticação |
| `ClearAuthCookies(c)` | Limpa cookies de autenticação |
| `GetTokenFromRequest(c)` | Extrai token da requisição |
| `AuthMiddleware(validateFunc)` | Cria um middleware para autenticação JWT |
| `AuthMiddlewareWithConfig(config, validateFunc)` | Cria um middleware para autenticação JWT com configuração |
| `RequirePermission(permissions...)` | Cria um middleware que requer permissões específicas |
| `RequireRole(roles...)` | Cria um middleware que requer roles específicas |
| `RequireAllRoles(roles...)` | Cria um middleware que requer todas as roles especificadas |
| `RequireAllPermissions(permissions...)` | Cria um middleware que requer todas as permissões especificadas |

### Token Blacklist

| Método | Descrição |
|--------|-------------|
| `NewTokenBlacklist(redisClient)` | Cria uma nova blacklist de tokens |
| `RevokeToken(ctx, tokenString)` | Revoga um token específico |
| `IsTokenRevoked(ctx, tokenString)` | Verifica se um token foi revogado |
| `RevokeAllUserTokens(ctx, userID)` | Revoga todos os tokens de um usuário |
| `IsUserTokensRevoked(ctx, userID, tokenIssuedAt)` | Verifica se tokens do usuário foram revogados |

### JWT Key Rotation

| Método | Descrição |
|--------|-------------|
| `NewJWTKeyManager(initialKey, initialKid)` | Cria um novo gerenciador de chaves |
| `AddKey(kid, secret)` | Adiciona uma nova chave |
| `SetCurrentKey(kid)` | Define a chave atual para novos tokens |
| `GetCurrentKey()` | Retorna a chave atual |
| `GetKey(kid)` | Retorna uma chave específica |
| `RemoveKey(kid)` | Remove uma chave (exceto a atual) |
| `GenerateTokenWithRotation(claims, expiry)` | Gera token com chave atual |
| `ValidateTokenWithRotation(tokenString, claims)` | Valida token com chave apropriada |

### Audit Signatures

| Método | Descrição |
|--------|-------------|
| `NewAuditSignature(secretKey)` | Cria um novo gerador de assinatura de auditoria |
| `GenerateOperationSignature(...)` | Gera assinatura para operação de auditoria |
| `VerifyOperationSignature(...)` | Verifica uma assinatura de operação de auditoria |

### Roles & Permissions Security

| Método | Descrição |
|--------|-------------|
| `NewRolesSignature(secretKey)` | Cria um novo gerador de assinatura de roles |
| `GenerateRolesSignature(userID, roles, timestamp)` | Gera assinatura para roles de usuário |
| `VerifyRolesSignature(userID, roles, timestamp, signature)` | Verifica assinatura de roles |
| `GeneratePermissionsSignature(userID, permissions, timestamp)` | Gera assinatura para permissões de usuário |
| `VerifyPermissionsSignature(userID, permissions, timestamp, signature)` | Verifica assinatura de permissões |
| `CreateSignedUserRoles(userID, roles, permissions, modifiedBy)` | Cria dados de roles/permissões assinados |
| `ValidateUserRoles(data)` | Valida assinaturas de roles e permissões |

### User Roles Helper

| Método | Descrição |
|--------|-------------|
| `NewUserRolesHelper(rolesSignature)` | Cria um novo helper de roles de usuário |
| `GetUserRolesAndPermissions(ctx, userID, userRolesData)` | Obtém roles e permissões validadas para um usuário |
| `UpdateUserRoles(userID, newRoles, modifiedBy)` | Atualiza roles de usuário com nova assinatura |
| `UpdateUserPermissions(userID, newPermissions, modifiedBy)` | Atualiza permissões de usuário com nova assinatura |
| `CreateJWTClaims(ctx, userID, userName, userEmail, tenantID, userRolesData)` | Cria claims JWT com roles/permissões validadas |

### Security Features

| Método | Descrição |
|--------|-------------|
| `CSRFMiddleware()` | Cria um middleware para proteção CSRF |
| `SetCSRFToken(c)` | Define um token CSRF para a sessão atual |
| `GenerateCSRFToken()` | Gera um novo token CSRF |
| `RateLimiterMiddleware(config)` | Cria um middleware para rate limiting |
| `DefaultRateLimiterConfig()` | Retorna configuração padrão do rate limiter |

### BSON Helpers

| Método | Descrição |
|--------|-------------|
| `MarshalWithRegistry(val)` | Marshals com registry customizado |
| `UnmarshalWithRegistry(data, val)` | Unmarshals com registry customizado |

### Sistema de Permissões

O framework implementa um sistema de permissões baseado em JWT onde:

- **Roles**: MASTER, ADMIN, USER, EXTERNAL, TENANT-OWNER (lista fixa)
- **Permissions**: Definidas por grupos e incluídas no JWT
- **Segurança**: Assinaturas digitais previnem adulteração
- **Performance**: Leitura apenas do JWT, zero consultas ao banco

```go
// Registrar sistema de assinaturas para roles
framework.RegisterRolesSignature("sua-chave-secreta-roles")
framework.RegisterUserRolesHelper()

// Registrar endpoints de autenticação (apenas JWT decode)
framework.RegisterAuthEndpoints()

// Endpoints disponíveis:
// POST /api/auth/check-role - Verifica roles do JWT
// POST /api/auth/check-permission - Verifica permissions do JWT
// GET /api/auth/permissions - Retorna roles + permissions do JWT

// Se você precisar de repositórios customizados, registre-os ANTES de chamar RegisterAuthEndpoints:
// framework.RegisterGroupRepository(NewCustomGroupRepository)
// framework.RegisterUserGroupMappingRepository(NewCustomMappingRepository)
// framework.RegisterAuthEndpoints()

// Exemplo de implementação de repositório de grupo
type GroupRepository struct {
    repo zensframework.IRepository[zensframework.Group]
}

func NewGroupRepository(db *mongo.Database, monitoring *zensframework.Monitoring, v *viper.Viper) *GroupRepository {
    return &GroupRepository{
        repo: zensframework.NewMongoDbRepository[zensframework.Group](db, monitoring, v),
    }
}

// Exemplo de implementação de repositório de mapeamento usuário-grupo
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

// Usando o group manager para verificar permissões
framework.Invoke(func(groupManager *zensframework.GroupManager) {
    // Verificar se usuário tem todas as permissões requeridas
    allowed, err := groupManager.CheckUserPermissions(ctx, userID, []string{"users:read", "users:write"})
    
    // Obter todas as permissões de um usuário
    permissions, err := groupManager.GetUserPermissions(ctx, userID)
    
    // Adicionar usuário a um grupo
    err := groupManager.AddUserToGroup(ctx, userID, groupID)
    
    // Remover usuário de um grupo
    err := groupManager.RemoveUserFromGroup(ctx, userID, groupID)
})

// Endpoints de autenticação para verificação de permissões
// POST /api/auth/check-role - Verificar se usuário tem todas as roles especificadas
// POST /api/auth/check-permission - Verificar se usuário tem todas as permissões especificadas
// GET /api/auth/permissions - Obter todas as permissões do usuário atual

// Exemplo de requisição para verificar roles
// POST /api/auth/check-role
// {"roles": ["ADMIN", "MANAGER"]}

// Exemplo de resposta
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

// Padrão de nomenclatura de permissões: [domínio]:[ação]-[escopo]
// Exemplos:
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

// Sistema Seguro de Roles & Permissões
// Registrar sistema de assinaturas para roles
framework.RegisterRolesSignature("your-roles-secret-key")
framework.RegisterUserRolesHelper()

// Usando sistema seguro de roles
framework.Invoke(func(userRolesHelper *zensframework.UserRolesHelper) {
    // Atualizar roles de usuário com segurança
    userRolesData, err := userRolesHelper.UpdateUserRoles(
        userID, 
        []string{"ADMIN", "USER"}, 
        "admin-user-id",
    )
    
    // Criar claims JWT com roles/permissões validadas
    claims, err := userRolesHelper.CreateJWTClaims(
        ctx, userID, userName, userEmail, tenantID, userRolesData,
    )
    
    // Gerar token JWT
    token, err := jwtHelper.GenerateToken(claims, time.Hour)
})

// Recursos de Segurança:
// - Roles: MASTER, ADMIN, USER, EXTERNAL, TENANT-OWNER (lista fixa)
// - Assinaturas digitais previnem adulteração no MongoDB
// - Assinaturas inválidas fazem fallback para role "USER"
// - Permissões combinam diretas + grupos
// - HMAC SHA256 com chave secreta apenas no código
```