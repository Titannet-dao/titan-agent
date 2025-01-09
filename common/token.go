package common

import (
	"context"
	"crypto/rsa"

	"github.com/gbrlsnchs/jwt/v3"
)

type JwtPayload struct {
	NodeID string
}

func AuthNew(ctx context.Context, payload *JwtPayload, priKey *rsa.PrivateKey) (string, error) {
	rs256 := jwt.NewRS256(jwt.RSAPrivateKey(priKey))
	tk, err := jwt.Sign(payload, rs256)
	return string(tk), err
}
