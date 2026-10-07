// Package keypin pins a long-term raw public key by its sha256 hex fingerprint.
// panel 与 agent 各自内嵌同一份，必须与 scripts/check-embedded-copies.sh 对照的副本一致。
package keypin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Fingerprint returns the hex sha256 of a raw public key.
func Fingerprint(rawPub []byte) string {
	sum := sha256.Sum256(rawPub)
	return hex.EncodeToString(sum[:])
}

// Match checks a raw public key against an expected hex fingerprint.
func Match(rawPub []byte, want string) error {
	got := Fingerprint(rawPub)
	if len(got) != len(want) {
		return errors.New("panel identity pin mismatch")
	}
	diff := 0
	for i := 0; i < len(got); i++ {
		diff |= int(got[i] ^ want[i])
	}
	if diff != 0 {
		return errors.New("panel identity pin mismatch")
	}
	return nil
}
