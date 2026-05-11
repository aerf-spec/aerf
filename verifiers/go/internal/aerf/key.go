package aerf

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Ed25519PublicKeyPrefix is the 12-byte SPKI prefix for Ed25519 per
// RFC 8410. A conformant public key is this prefix followed by the
// 32-byte raw key.
var Ed25519PublicKeyPrefix = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x70, 0x03, 0x21, 0x00,
}

// LoadPublicKeyFile reads an Ed25519 public key from a PEM file.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(b)
}

// ParsePublicKey decodes an Ed25519 public key from SPKI PEM bytes.
func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q (want PUBLIC KEY)", block.Type)
	}
	der := block.Bytes
	want := len(Ed25519PublicKeyPrefix) + ed25519.PublicKeySize
	if len(der) != want {
		return nil, fmt.Errorf("SPKI length %d (want %d)", len(der), want)
	}
	if !bytes.Equal(der[:len(Ed25519PublicKeyPrefix)], Ed25519PublicKeyPrefix) {
		return nil, errors.New("SPKI prefix is not Ed25519 (RFC 8410)")
	}
	return ed25519.PublicKey(der[len(Ed25519PublicKeyPrefix):]), nil
}
