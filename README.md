# Zensegur Framework

Framework genérico para repositórios Firestore com suporte a multi-tenant e injeção de cabeçalhos.

## Instalação

```bash
go get github.com/azzidev/zensegur-framework
```

## Uso Básico

```go
package main

import (
    "context"
    "github.com/azzidev/zensegur-framework"
)

type User struct {
    Username string `firestore:"username" validate:"required"`
    Email    string `firestore:"email" validate:"required,email"`
    zensegur.BaseDocument // Adiciona created, updated, deleted_at, active
}

func main() {
    ctx := context.Background()
    
    // Criar cliente
    client, err := zensegur.NewClient(ctx, "your-project-id")
    if err != nil {
        panic(err)
    }
    defer client.Close()
    
    // Usar com tenant
    userRepo := client.WithTenant("empresa1").Repository("users")
    
    // Buscar com filtros (tipo MongoDB)
    var users []User
    err = userRepo.Where("active", "==", true).
        Where("username", ">=", "a").
        OrderBy("username", false).
        Limit(10).
        Skip(0).
        Execute(&users)
    
    // Buscar primeiro com filtro
    var user User
    err = userRepo.Where("username", "==", "admin").First(&user)
    
    // Buscar todos (sem filtro)
    var allUsers []User
    err = userRepo.GetAll(&allUsers)
    
    // Com metadados automáticos
    authorRepo := userRepo.WithAuthor("user123", "João Silva")
    id, err := authorRepo.Create(user) // Adiciona created/updated automaticamente
}
```

## Métodos Disponíveis

### Busca Simples
- `GetFirst(result, field, value)` - Busca primeiro registro
- `GetByID(id, result)` - Busca por ID
- `GetAll(results)` - Busca todos os registros
- `GetAllSkipTake(results, skip, take)` - Busca com paginação

### Query Builder (tipo MongoDB)
- `Where(field, op, value)` - Adiciona filtro
- `OrderBy(field, desc)` - Ordena resultados
- `Limit(n)` - Limita resultados
- `Skip(n)` - Pula registros
- `Execute(results)` - Executa query
- `First(result)` - Primeiro resultado da query

### CRUD Avançado
- `Create(data)` - Cria novo registro (retorna ID)
- `CreateWithID(id, data)` - Cria com ID específico
- `Update(id, data)` - Atualiza registro completo
- `UpdateFields(id, fields)` - Atualiza campos específicos
- `Delete(id)` - Deleta registro
- `SoftDelete(id)` - Soft delete (marca como inativo)

### Funcionalidades Avançadas
- `Count()` - Conta registros
- `Exists(field, value)` - Verifica se existe
- `RunTransaction(fn)` - Executa transação
- `NewBatch()` - Operações em lote
- `WithAudit(userID)` - Habilita auditoria
- `WithCache(cache)` - Habilita cache
- `WithValidation(validator)` - Habilita validação

### Operadores Suportados
- `==` - Igual
- `!=` - Diferente
- `<` - Menor que
- `<=` - Menor ou igual
- `>` - Maior que
- `>=` - Maior ou igual
- `array-contains` - Array contém
- `in` - Está em array
- `not-in` - Não está em array

## Funcionalidades Extras

### Cache em Memória
```go
cache := zensegur.NewCache(5 * time.Minute)
repo := userRepo.WithCache(cache)
```

### Auditoria Automática
```go
// Todas as operações serão auditadas
auditRepo := userRepo.WithAudit("user123")
auditRepo.Create(user) // Gera log de auditoria
```

### Validação com Tags
```go
type User struct {
    Email string `validate:"required,email"`
    Name  string `validate:"required"`
}

validator := zensegur.NewValidator()
repo := userRepo.WithValidation(validator)
```

### Middleware de Autenticação
```go
// Implementar interface Claims
type UserClaims struct {
    UserID   string   `json:"sub"`
    Username string   `json:"username"`
    Roles    []string `json:"roles"`
    Permissions []string `json:"permissions"`
}

func (u *UserClaims) GetUserID() string { return u.UserID }
func (u *UserClaims) GetUsername() string { return u.Username }
func (u *UserClaims) GetRoles() []string { return u.Roles }
func (u *UserClaims) GetPermissions() []string { return u.Permissions }

// Usar middleware
r.Use(zensegur.AuthMiddleware(myJWTValidator))
r.GET("/admin", zensegur.RequireRole("admin"), handler)
r.GET("/users", zensegur.RequirePermission("users.read"), handler)
```

### Metadados Automáticos
```go
// Todos os documentos terão automaticamente:
type MyDocument struct {
    Name string `firestore:"name"`
    zensegur.BaseDocument // created, updated, deleted_at, active
}

// Usar com autor
repo := userRepo.WithAuthor("user123", "João Silva")
id, err := repo.Create(doc) // Adiciona created/updated automaticamente
repo.Update(id, doc)        // Atualiza updated automaticamente
repo.Delete(id)             // Soft delete (marca deleted_at)
```

## Características Importantes

- **Collection por Tenant**: `empresa1_users`, `empresa2_users` (sem campo tenant no documento)
- **Apenas Soft Delete**: Delete físico removido, só soft delete
- **Metadados Automáticos**: created/updated em todas operações
- **Thread Safe**: Todas operações são thread-safe