package proxy

import (
	"crypto/sha256"
	"encoding/hex"
)

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
