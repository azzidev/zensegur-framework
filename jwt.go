package zensegur

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims interface {
	GetUserID() string
	GetUsername() string
	GetRoles() []string
	GetPermissions() []string
}

type JWTClaims struct {
	UserID      string   `json:"sub"`
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

func (c *JWTClaims) GetUserID() string        { return c.UserID }
func (c *JWTClaims) GetUsername() string      { return c.Username }
func (c *JWTClaims) GetRoles() []string       { return c.Roles }
func (c *JWTClaims) GetPermissions() []string { return c.Permissions }

var jwtSecret = []byte("TOKEN_SECRET")

func GenerateJWT(userID, username string, roles, permissions []string) (string, error) {
	claims := &JWTClaims{
		UserID:      userID,
		Username:    username,
		Roles:       roles,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ValidateJWT(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
