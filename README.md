# ZenSegur Framework

Framework MongoDB para Go com suporte a multi-tenant, cache, auditoria e validação.

## Instalação

```bash
go get github.com/azzidev/zensegur-framework
```

## Uso Básico

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/azzidev/zensegur-framework"
)

// Definir modelo
type User struct {
    ID       string `bson:"_id,omitempty" json:"id,omitempty"`
    Username string `bson:"username" json:"username"`
    Email    string `bson:"email" json:"email"`
    zensegur.BaseDocument // Adiciona created_at, updated_at, deleted_at, active, etc.
}

func main() {
    // Criar cliente
    ctx := context.Background()
    client, err := zensegur.NewClient(ctx, "mongodb://localhost:27017", "zensegur")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Criar cache
    cache := zensegur.NewCache(5 * time.Minute)
    
    // Configurar cliente com tenant e autor
    clientWithContext := client.
        WithTenant("empresa1").
        WithAuthor("user123", "João Silva").
        WithAudit(true).
        WithCache(cache)
    
    // Criar repositório tipado
    userRepo := clientWithContext.RepositoryTyped("users").(*zensegur.MongoRepository[User])
    
    // Criar usuário
    user := User{
        Username: "joao.silva",
        Email:    "joao@example.com",
    }
    
    // Inserir usuário (metadados são adicionados automaticamente)
    err = userRepo.Insert(ctx, &user)
    if err != nil {
        log.Fatal(err)
    }
    
    // Buscar usuários com filtro
    filter := map[string]interface{}{
        "username": "joao.silva",
    }
    
    // Buscar primeiro usuário
    foundUser := userRepo.GetFirst(ctx, filter)
    if foundUser != nil {
        log.Printf("Usuário encontrado: %s", foundUser.Email)
    }
    
    // Buscar todos os usuários
    allUsers := userRepo.GetAll(ctx, map[string]interface{}{})
    log.Printf("Total de usuários: %d", len(*allUsers))
    
    // Atualizar usuário
    updateFields := map[string]interface{}{
        "email": "joao.novo@example.com",
    }
    err = userRepo.Update(ctx, filter, updateFields)
    if err != nil {
        log.Fatal(err)
    }
    
    // Soft delete (mantém o registro mas marca como inativo)
    err = userRepo.Delete(ctx, filter)
    if err != nil {
        log.Fatal(err)
    }
}
```

## Recursos Principais

### Cliente

```go
// Criar cliente
client, err := zensegur.NewClient(ctx, "mongodb://localhost:27017", "zensegur")

// Configurar cliente
client = client.WithTenant("empresa1")
client = client.WithAuthor("user123", "João Silva")
client = client.WithAudit(true)
client = client.WithCache(cache)

// Obter repositório
repo := client.Repository("collection")
```

### Repositório

```go
// Busca simples
user := repo.GetFirst(ctx, map[string]interface{}{"username": "admin"})
users := repo.GetAll(ctx, map[string]interface{}{"active": true})

// Paginação
result := repo.GetAllSkipTake(ctx, filter, 0, 10)
log.Printf("Total: %d, Itens: %d", result.TotalCount, len(result.Items))

// CRUD
id, err := repo.Insert(ctx, &user)
err = repo.Update(ctx, filter, updateFields)
err = repo.Delete(ctx, filter) // Soft delete
err = repo.DeleteForce(ctx, filter) // Hard delete

// Operações em lote
err = repo.InsertAll(ctx, &users)
err = repo.UpdateMany(ctx, filter, fields)
err = repo.DeleteMany(ctx, filter)

// Arrays
err = repo.PushMany(ctx, filter, map[string]interface{}{"tags": "novo"})
err = repo.PullMany(ctx, filter, map[string]interface{}{"tags": "remover"})
```

### Query Builder

```go
// Iniciar query
query := repo.Where("username", "==", "admin")

// Adicionar filtros
query = query.Where("active", "==", true)
query = query.Where("age", ">", 18)

// Ordenação e paginação
query = query.OrderBy("created_at", true) // true = descendente
query = query.Skip(10).Limit(5)

// Executar consulta
users, err := query.Execute()

// Buscar primeiro resultado
var user User
err = query.First(&user)
```

### Cache

```go
// Criar cache
cache := zensegur.NewCache(5 * time.Minute)

// Usar cache
repo := repo.WithCache(cache)

// Operações manuais
cache.Set("key", value)
cache.SetWithExpiration("key", value, 10*time.Minute)
value := cache.Get("key")
cache.Delete("key")
cache.Delete("prefix*") // Wildcard
```

### Auditoria

```go
// Habilitar auditoria
repo := repo.WithAudit(true)

// A auditoria é automática para Insert, Update e Delete
// Os logs são armazenados na coleção "audit_logs"
```

### Validação

```go
// Criar validador
validator := zensegur.NewValidator()

// Adicionar regras
validator.AddRule("phone", func(v interface{}) error {
    // Validação personalizada
    return nil
})

// Usar validador
repo := repo.WithValidation(validator)

// Validar manualmente
type Product struct {
    Name  string `validate:"required"`
    Email string `validate:"email"`
    Phone string `validate:"phone"`
}

product := Product{...}
err := validator.Validate(product)
```

### Multi-Tenant

```go
// Configurar tenant
client := client.WithTenant("empresa1")

// O tenant é aplicado automaticamente:
// 1. Prefixo na collection: "empresa1_users"
// 2. Filtro automático em consultas
```

### Gin Middleware

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/azzidev/zensegur-framework"
)

func jwtValidator(token string) (zensegur.Claims, error) {
    return zensegur.ValidateJWT(token)
}

func setupRouter() *gin.Engine {
    r := gin.Default()
    
    // Middlewares de autenticação
    r.Use(zensegur.GinAuthMiddleware(jwtValidator))
    r.Use(zensegur.GinCookieAuthMiddleware(jwtValidator, "auth-token"))
    
    // Middlewares de autorização
    r.GET("/admin", zensegur.GinRequireRole("admin"), handler)
    r.GET("/users", zensegur.GinRequirePermission("users.read"), handler)
    
    // Middlewares de segurança
    r.Use(zensegur.GinCORSMiddleware())
    r.Use(zensegur.GinSecurityMiddleware())
    r.Use(zensegur.GinRateLimitMiddleware(100, 60)) // 100 req/min
    r.Use(zensegur.GinTenantMiddleware())
    
    // Helpers
    r.GET("/profile", func(c *gin.Context) {
        userID := zensegur.GinGetUserID(c)
        username := zensegur.GinGetUsername(c)
        tenant := zensegur.GinGetTenant(c)
        // ...
    })
    
    return r
}
```

### JWT

```go
// Gerar token
token, err := zensegur.GenerateJWT(
    "user123",
    "joao.silva",
    []string{"admin", "user"},
    []string{"users.read", "users.write"},
)

// Validar token
claims, err := zensegur.ValidateJWT(token)
if err != nil {
    // Token inválido
}

// Acessar claims
userID := claims.GetUserID()
username := claims.GetUsername()
roles := claims.GetRoles()
permissions := claims.GetPermissions()
```

### Resolver Tenant

```go
// Resolver tenant a partir do username (formato: user@tenant)
client, username, err := client.ResolveUserTenant("joao@empresa1")
if err != nil {
    // Tenant não encontrado
}

// O client já está configurado com o tenant correto
repo := client.Repository("users")
```

## Estruturas de Dados

### BaseDocument

```go
type BaseDocument struct {
    CreatedAt  time.Time  `bson:"created_at" json:"created_at"`
    UpdatedAt  time.Time  `bson:"updated_at" json:"updated_at"`
    DeletedAt  *time.Time `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`
    Active     bool       `bson:"active" json:"active"`
    CreatedBy  string     `bson:"created_by,omitempty" json:"created_by,omitempty"`
    UpdatedBy  string     `bson:"updated_by,omitempty" json:"updated_by,omitempty"`
}
```

### Interfaces

```go
// Implementar estas interfaces para suporte a metadados
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

// BaseDocument já implementa todas estas interfaces
```

## Características Importantes

- **Collection por Tenant**: `empresa1_users`, `empresa2_users`
- **Apenas Soft Delete**: Delete físico disponível via `DeleteForce`
- **Metadados Automáticos**: created_at/updated_at em todas operações
- **Cache Inteligente**: Invalidação automática em operações de escrita
- **Thread Safe**: Todas operações são thread-safe
- **Zero Reflection**: Uso mínimo de reflection apenas para metadados