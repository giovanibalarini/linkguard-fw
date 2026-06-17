// Package auth handles user authentication using JWT tokens.
package auth

import (
"errors"
"fmt"
"time"

"github.com/golang-jwt/jwt/v5"
"golang.org/x/crypto/bcrypt"

"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const tokenExpiry = 24 * time.Hour

// Claims are the JWT payload claims.
type Claims struct {
UserID   string `json:"user_id"`
Username string `json:"username"`
Role     string `json:"role"`
jwt.RegisteredClaims
}

// Service handles authentication.
type Service struct {
db        *storage.DB
jwtSecret []byte
}

// NewService creates a new auth Service.
func NewService(db *storage.DB, jwtSecret string) *Service {
return &Service{db: db, jwtSecret: []byte(jwtSecret)}
}

// Login authenticates a user and returns a JWT token.
func (s *Service) Login(username, rawPassword string) (string, *storage.User, error) {
user, err := s.db.GetUserByUsername(username)
if err != nil {
return "", nil, fmt.Errorf("lookup user: %w", err)
}
if user == nil {
return "", nil, errors.New("invalid credentials")
}

if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(rawPassword)); err != nil {
return "", nil, errors.New("invalid credentials")
}

token, err := s.generateToken(user)
if err != nil {
return "", nil, err
}

return token, user, nil
}

func (s *Service) generateToken(user *storage.User) (string, error) {
claims := Claims{
UserID:   user.ID,
Username: user.Username,
Role:     user.Role,
RegisteredClaims: jwt.RegisteredClaims{
ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiry)),
IssuedAt:  jwt.NewNumericDate(time.Now()),
Subject:   user.ID,
},
}
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
return token.SignedString(s.jwtSecret)
}

// ValidateToken parses and validates a JWT token, returning its claims.
func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
}
return s.jwtSecret, nil
})
if err != nil {
return nil, err
}

claims, ok := token.Claims.(*Claims)
if !ok || !token.Valid {
return nil, errors.New("invalid token")
}
return claims, nil
}

// HashPassword generates a bcrypt hash of the given password.
func HashPassword(plain string) (string, error) {
hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
if err != nil {
return "", err
}
return string(hash), nil
}
