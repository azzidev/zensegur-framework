package zensframework

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// JWTKeyManager gerencia múltiplas chaves JWT para rotação
type JWTKeyManager struct {
	keys       map[string]string // kid -> secret
	currentKid string
	mutex      sync.RWMutex
}

// NewJWTKeyManager cria um novo gerenciador de chaves
func NewJWTKeyManager(initialKey string, initialKid string) *JWTKeyManager {
	return &JWTKeyManager{
		keys: map[string]string{
			initialKid: initialKey,
		},
		currentKid: initialKid,
	}
}

// AddKey adiciona uma nova chave
func (km *JWTKeyManager) AddKey(kid, secret string) {
	km.mutex.Lock()
	defer km.mutex.Unlock()
	km.keys[kid] = secret
}

// SetCurrentKey define a chave atual para novos tokens
func (km *JWTKeyManager) SetCurrentKey(kid string) error {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	if _, exists := km.keys[kid]; !exists {
		return fmt.Errorf("key with id %s not found", kid)
	}

	km.currentKid = kid
	return nil
}

// GetCurrentKey retorna a chave atual
func (km *JWTKeyManager) GetCurrentKey() (string, string) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	return km.currentKid, km.keys[km.currentKid]
}

// GetKey retorna uma chave específica
func (km *JWTKeyManager) GetKey(kid string) (string, bool) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()
	secret, exists := km.keys[kid]
	return secret, exists
}

// RemoveKey remove uma chave (exceto a atual)
func (km *JWTKeyManager) RemoveKey(kid string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	if kid == km.currentKid {
		return fmt.Errorf("cannot remove current key")
	}

	delete(km.keys, kid)
	return nil
}

// JWTHelperWithRotation extends JWTHelper with key rotation support
type JWTHelperWithRotation struct {
	*JWTHelper
	keyManager *JWTKeyManager
}

// NewJWTHelperWithRotation cria um JWTHelper com suporte a rotação de chaves
func NewJWTHelperWithRotation(config *JWTConfig, keyManager *JWTKeyManager) *JWTHelperWithRotation {
	return &JWTHelperWithRotation{
		JWTHelper:  NewJWTHelper(config),
		keyManager: keyManager,
	}
}

// GenerateTokenWithRotation gera um token com a chave atual
func (h *JWTHelperWithRotation) GenerateTokenWithRotation(claims jwt.Claims, expiry time.Duration) (string, error) {
	currentKid, currentSecret := h.keyManager.GetCurrentKey()

	if mapClaims, ok := claims.(jwt.MapClaims); ok {
		// Add standard claims
		if h.config.Issuer != "" {
			if _, exists := mapClaims["iss"]; !exists {
				mapClaims["iss"] = h.config.Issuer
			}
		}

		if _, exists := mapClaims["jti"]; !exists {
			mapClaims["jti"] = uuid.New().String()
		}

		if _, exists := mapClaims["iat"]; !exists {
			mapClaims["iat"] = time.Now().Unix()
		}
	}

	// Create token with kid in header
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = currentKid

	return token.SignedString([]byte(currentSecret))
}

// ValidateTokenWithRotation valida um token usando a chave apropriada
func (h *JWTHelperWithRotation) ValidateTokenWithRotation(tokenString string, claims jwt.Claims) error {
	// Parse token to get kid from header
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get kid from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			// Fallback to current key if no kid
			_, currentSecret := h.keyManager.GetCurrentKey()
			return []byte(currentSecret), nil
		}

		// Get secret for this kid
		secret, exists := h.keyManager.GetKey(kid)
		if !exists {
			return nil, fmt.Errorf("unknown key id: %s", kid)
		}

		return []byte(secret), nil
	})

	// Handle parsing errors
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return ErrTokenExpired
			}
		}
		return ErrInvalidToken
	}

	if !token.Valid {
		return ErrInvalidToken
	}

	// Verify issuer
	if h.config.Issuer != "" {
		if mapClaims, ok := claims.(jwt.MapClaims); ok {
			if issuer, ok := mapClaims["iss"].(string); !ok || issuer != h.config.Issuer {
				return ErrInvalidToken
			}
		}
	}

	return nil
}

// RegisterJWTKeyManager registra o gerenciador de chaves no framework
func (zsf *ZSFramework) RegisterJWTKeyManager(initialKey, initialKid string) {
	err := zsf.ioc.Provide(func() *JWTKeyManager {
		return NewJWTKeyManager(initialKey, initialKid)
	})
	if err != nil {
		panic(err)
	}
}
