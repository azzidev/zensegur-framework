package zensframework

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt"
)

// TokenBlacklist gerencia tokens revogados usando Redis
type TokenBlacklist struct {
	redisClient *redis.Client
}

// NewTokenBlacklist cria uma nova instância do blacklist
func NewTokenBlacklist(redisClient *redis.Client) *TokenBlacklist {
	return &TokenBlacklist{
		redisClient: redisClient,
	}
}

// RevokeToken adiciona um token à blacklist
func (tb *TokenBlacklist) RevokeToken(ctx context.Context, tokenString string) error {
	// Parse token para extrair jti e exp
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	// Extrai jti (JWT ID)
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return fmt.Errorf("token missing jti claim")
	}

	// Extrai exp (expiration time)
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("token missing exp claim")
	}

	// Calcula TTL baseado na expiração do token
	expTime := time.Unix(int64(exp), 0)
	ttl := time.Until(expTime)
	
	// Se o token já expirou, não precisa adicionar à blacklist
	if ttl <= 0 {
		return nil
	}

	// Adiciona jti à blacklist com TTL
	key := fmt.Sprintf("blacklist:token:%s", jti)
	return tb.redisClient.Set(ctx, key, "revoked", ttl).Err()
}

// IsTokenRevoked verifica se um token está na blacklist
func (tb *TokenBlacklist) IsTokenRevoked(ctx context.Context, tokenString string) (bool, error) {
	// Parse token para extrair jti
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid token claims")
	}

	// Extrai jti
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		// Se não tem jti, considera como não revogado (compatibilidade)
		return false, nil
	}

	// Verifica se existe na blacklist
	key := fmt.Sprintf("blacklist:token:%s", jti)
	result := tb.redisClient.Exists(ctx, key)
	if result.Err() != nil {
		return false, result.Err()
	}

	return result.Val() > 0, nil
}

// RevokeAllUserTokens revoga todos os tokens de um usuário
func (tb *TokenBlacklist) RevokeAllUserTokens(ctx context.Context, userID string) error {
	// Adiciona o usuário à lista de usuários com tokens revogados
	key := fmt.Sprintf("blacklist:user:%s", userID)
	// TTL de 7 dias (tempo máximo de vida de um refresh token)
	return tb.redisClient.Set(ctx, key, time.Now().Unix(), 7*24*time.Hour).Err()
}

// IsUserTokensRevoked verifica se todos os tokens de um usuário foram revogados
func (tb *TokenBlacklist) IsUserTokensRevoked(ctx context.Context, userID string, tokenIssuedAt int64) (bool, error) {
	key := fmt.Sprintf("blacklist:user:%s", userID)
	result := tb.redisClient.Get(ctx, key)
	
	if result.Err() == redis.Nil {
		// Não há revogação para este usuário
		return false, nil
	}
	
	if result.Err() != nil {
		return false, result.Err()
	}

	// Compara o timestamp de revogação com o timestamp de emissão do token
	revokedAt, err := result.Int64()
	if err != nil {
		return false, err
	}

	// Se o token foi emitido antes da revogação, está revogado
	return tokenIssuedAt < revokedAt, nil
}

// RegisterTokenBlacklist registra o blacklist no framework
func (gf *GoFramework) RegisterTokenBlacklist() {
	gf.Invoke(func(redisClient *redis.Client) {
		err := gf.ioc.Provide(func() *TokenBlacklist {
			return NewTokenBlacklist(redisClient)
		})
		if err != nil {
			panic(err)
		}
	})
}