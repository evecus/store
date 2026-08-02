package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Claims is the JWT payload.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var errInvalidToken = errors.New("invalid token")

func (s *Server) signToken(username string) (string, error) {
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.Cfg.TokenTTLHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.Cfg.JWTSecret))
}

// validateToken parses and validates a JWT, returning the username.
func (s *Server) validateToken(raw string) (string, error) {
	token, err := jwt.ParseWithClaims(raw, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(s.Cfg.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return "", errInvalidToken
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", errInvalidToken
	}
	return claims.Username, nil
}

// authMiddleware validates the Authorization bearer token.
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			abortError(c, http.StatusUnauthorized, "missing bearer token")
			return
		}
		username, err := s.validateToken(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			abortError(c, http.StatusUnauthorized, "invalid token")
			return
		}
		c.Set("username", username)
		c.Next()
	}
}

// dummyHash is compared against on unknown-username login attempts so the
// response time doesn't reveal whether the username exists (bcrypt is the
// dominant cost in this handler).
const dummyHash = "$2a$10$C6UzMDM.H6dfI/f/IKcEeO/em4T1G.9k6bfV8kEZfW2fF6Hna5J8y"

func (s *Server) handleLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	u, err := s.Store.GetUser(body.Username)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "database error")
		return
	}
	hash := dummyHash
	if u != nil {
		hash = u.PasswordHash
	}
	pwOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) == nil
	if u == nil || !pwOK {
		abortError(c, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, err := s.signToken(body.Username)
	if err != nil {
		abortError(c, http.StatusInternalServerError, "sign token failed")
		return
	}
	if key, ok := c.Get("rateLimitKey"); ok {
		if k, ok := key.(string); ok {
			s.loginLimiter.reset(k)
		}
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "username": body.Username})
}

func (s *Server) handleMe(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"username": currentUser(c)})
}
