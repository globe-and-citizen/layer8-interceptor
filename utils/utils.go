package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type JWTClaims struct {
	Issuer string `json:"iss"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
}

func ParseJWT(token string) (exp int64, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid JWT format")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, fmt.Errorf("error decoding payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return 0, fmt.Errorf("error parsing claims: %w", err)
	}

	return claims.Exp, nil
}

func CheckJwtExpiry(exp int64) error {
	currentTime := time.Now().Unix()
	if currentTime > exp {
		return fmt.Errorf("token has expired")
	}
	return nil
}