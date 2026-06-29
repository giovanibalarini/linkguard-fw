// Package auth handles user authentication using JWT tokens.
package auth

import (
"errors"
"fmt"
"strings"
"sync"
"time"

"github.com/golang-jwt/jwt/v5"
"golang.org/x/crypto/bcrypt"

"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const tokenExpiry = 24 * time.Hour

// Anti-brute-force: lock an account after too many failed attempts.
const (
maxFailedAttempts = 8
lockoutDuration   = 15 * time.Minute
)

// ErrTOTPRequired signals the password was correct but a 2FA code is needed.
var ErrTOTPRequired = errors.New("totp_required")

// ErrLockedOut signals the account is temporarily locked after repeated failures.
var ErrLockedOut = errors.New("locked_out")

type attemptInfo struct {
count     int
lockUntil time.Time
}

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

mu       sync.Mutex
attempts map[string]*attemptInfo
}

// NewService creates a new auth Service.
func NewService(db *storage.DB, jwtSecret string) *Service {
return &Service{db: db, jwtSecret: []byte(jwtSecret), attempts: map[string]*attemptInfo{}}
}

// Login authenticates a user (with optional 2FA code) and returns a JWT token.
// It enforces a lockout after repeated failures and TOTP when the user enabled
// it. ErrTOTPRequired is returned (with the user) when a code is still needed.
func (s *Service) Login(username, rawPassword, code string) (string, *storage.User, error) {
key := strings.ToLower(strings.TrimSpace(username))
if s.lockedOut(key) {
return "", nil, ErrLockedOut
}

user, err := s.db.GetUserByUsername(username)
if err != nil {
return "", nil, fmt.Errorf("lookup user: %w", err)
}
if user == nil {
s.recordFailure(key)
return "", nil, errors.New("invalid credentials")
}

if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(rawPassword)); err != nil {
s.recordFailure(key)
return "", nil, errors.New("invalid credentials")
}

// Password OK — enforce 2FA if enabled.
if s.TwoFAEnabled(user.ID) {
if strings.TrimSpace(code) == "" {
return "", user, ErrTOTPRequired
}
if !ValidateTOTP(s.getTwoFA(user.ID).Secret, code) {
s.recordFailure(key)
return "", nil, errors.New("invalid credentials")
}
}

s.resetAttempts(key)
token, err := s.generateToken(user)
if err != nil {
return "", nil, err
}
return token, user, nil
}

func (s *Service) lockedOut(key string) bool {
s.mu.Lock()
defer s.mu.Unlock()
a := s.attempts[key]
return a != nil && time.Now().Before(a.lockUntil)
}

func (s *Service) recordFailure(key string) {
s.mu.Lock()
defer s.mu.Unlock()
a := s.attempts[key]
if a == nil {
a = &attemptInfo{}
s.attempts[key] = a
}
a.count++
if a.count >= maxFailedAttempts {
a.lockUntil = time.Now().Add(lockoutDuration)
a.count = 0
}
}

func (s *Service) resetAttempts(key string) {
s.mu.Lock()
defer s.mu.Unlock()
delete(s.attempts, key)
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
