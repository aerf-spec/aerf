// AERF reference verifier — v0.1.0-draft.1
//
// Verifies the Ed25519 signature on a single AERF-EVIDENCE receipt against
// an Ed25519 public key in SPKI PEM form (RFC 8410). Standard library only.
//
// This reference verifier does NOT verify hash chains or RFC 3161
// timestamps. Both are described in the spec and will be added in a
// future draft. See ../../SPEC.md sections 8 and 11.
//
// Usage: aerf-verify <receipt.json> <public_key.pem>
// Exit:  0 = signature valid
//
//	1 = signature invalid or receipt malformed
//	2 = usage / I/O error
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"unicode/utf16"
)

const usage = "usage: aerf-verify <receipt.json> <public_key.pem>"

// Ed25519 SPKI prefix per RFC 8410: 12 bytes followed by the 32-byte raw key.
var spkiPrefix = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x70, 0x03, 0x21, 0x00,
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	receiptBytes, err := os.ReadFile(os.Args[1])
	if err != nil {
		exit(2, "read receipt: %v", err)
	}
	keyBytes, err := os.ReadFile(os.Args[2])
	if err != nil {
		exit(2, "read public key: %v", err)
	}

	pub, err := loadEd25519PublicKey(keyBytes)
	if err != nil {
		exit(2, "parse public key: %v", err)
	}

	var raw map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(receiptBytes))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		exit(2, "parse receipt: %v", err)
	}

	sigHex, ok := raw["signature"].(string)
	if !ok {
		exit(1, "receipt missing 'signature' field")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		exit(1, "signature is not valid hex: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		exit(1, "signature wrong length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	delete(raw, "signature")
	delete(raw, "timestamp")

	canonical, err := canonicalize(raw)
	if err != nil {
		exit(2, "canonicalize: %v", err)
	}

	if !ed25519.Verify(pub, canonical, sig) {
		exit(1, "signature verification FAILED for receipt %s", shortID(raw))
	}

	fmt.Printf("OK  receipt %s\n", shortID(raw))
	fmt.Printf("    type:      %v\n", raw["type"])
	fmt.Printf("    agent:     %v\n", raw["agent"])
	fmt.Printf("    action:    %v\n", raw["action"])
	fmt.Printf("    in_policy: %v\n", raw["in_policy"])
	fmt.Printf("    key_id:    %v\n", raw["key_id"])
}

func exit(code int, format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(code)
}

func shortID(r map[string]interface{}) string {
	id, ok := r["id"].(string)
	if !ok {
		return "<unknown>"
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func loadEd25519PublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q (want PUBLIC KEY)", block.Type)
	}
	der := block.Bytes
	if len(der) != len(spkiPrefix)+ed25519.PublicKeySize {
		return nil, fmt.Errorf("SPKI length %d (want %d)", len(der), len(spkiPrefix)+ed25519.PublicKeySize)
	}
	if !bytes.Equal(der[:len(spkiPrefix)], spkiPrefix) {
		return nil, errors.New("SPKI prefix is not Ed25519 (RFC 8410)")
	}
	return ed25519.PublicKey(der[len(spkiPrefix):]), nil
}

// canonicalize produces JSON bytes byte-identical to Python's
//
//	json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
//
// which is the canonicalization used by the v0.1.0-draft.1 reference
// producer (see SPEC.md §5.1). Numbers are preserved verbatim from the
// input via json.Number; strings are escaped to ASCII.
func canonicalize(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writePyString(buf, x)
	case json.Number:
		buf.WriteString(string(x))
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writePyString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return fmt.Errorf("unsupported JSON type %T", v)
	}
	return nil
}

// writePyString matches Python's json.dumps default string encoding
// (ensure_ascii=True, escape \" and \\, named escapes for \b \f \n \r \t,
// \u00XX for other control chars, \uXXXX for non-ASCII, surrogate pairs
// for code points above U+FFFF).
func writePyString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 || r > 0x7e {
				if r > 0xffff {
					hi, lo := utf16.EncodeRune(r)
					fmt.Fprintf(buf, `\u%04x\u%04x`, hi, lo)
				} else {
					fmt.Fprintf(buf, `\u%04x`, r)
				}
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
