package certpin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

func SPKI(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func Match(rawCert []byte, want string) error {
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return err
	}
	got := SPKI(cert)
	if len(got) != len(want) {
		return errors.New("panel certificate pin mismatch")
	}
	diff := 0
	for i := 0; i < len(got); i++ {
		diff |= int(got[i] ^ want[i])
	}
	if diff != 0 {
		return errors.New("panel certificate pin mismatch")
	}
	return nil
}
