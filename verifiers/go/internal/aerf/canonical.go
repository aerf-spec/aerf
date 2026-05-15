// Package aerf implements verification of AERF-EVIDENCE receipts per
// SPEC.md v0.2.0-draft.1. Standard library only.
package aerf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Canonical produces RFC 8785 (JCS) canonical JSON bytes for v.
//
// AERF tightenings on top of JCS are upstream of the verifier:
// strings must already be in Unicode NFC (SPEC.md §5.1, producer
// obligation), and numbers inside any object whose canonical bytes
// will be hashed into context_hash_sha256 must already be encoded as
// JSON strings. Numbers in the input are preserved verbatim via
// json.Number, which matches a strict JCS implementation for the
// field set v0.1 producers emitted.
func Canonical(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(w io.Writer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		_, err := io.WriteString(w, "null")
		return err
	case bool:
		if x {
			_, err := io.WriteString(w, "true")
			return err
		}
		_, err := io.WriteString(w, "false")
		return err
	case string:
		return writeJSONString(w, x)
	case json.Number:
		_, err := io.WriteString(w, string(x))
		return err
	case map[string]interface{}:
		return writeObject(w, x)
	case []interface{}:
		return writeArray(w, x)
	default:
		return fmt.Errorf("canonical: unsupported JSON type %T", v)
	}
}

func writeObject(w io.Writer, m map[string]interface{}) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	for i, k := range keys {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := writeJSONString(w, k); err != nil {
			return err
		}
		if _, err := io.WriteString(w, ":"); err != nil {
			return err
		}
		if err := writeCanonical(w, m[k]); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "}")
	return err
}

func writeArray(w io.Writer, arr []interface{}) error {
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	for i, item := range arr {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := writeCanonical(w, item); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "]")
	return err
}

// writeJSONString emits a JSON string per RFC 8785 §3.2.2.2: only the
// mandatory JSON escapes, control characters as \u00XX, raw UTF-8 for
// everything else. For ASCII input this is byte-identical to Python's
// json.dumps(ensure_ascii=True), which is what produced the v0.1
// example signature; that regression is intentional.
func writeJSONString(w io.Writer, s string) error {
	if _, err := io.WriteString(w, `"`); err != nil {
		return err
	}
	for _, r := range s {
		switch r {
		case '"':
			_, err := io.WriteString(w, `\"`)
			if err != nil {
				return err
			}
		case '\\':
			_, err := io.WriteString(w, `\\`)
			if err != nil {
				return err
			}
		case '\b':
			_, err := io.WriteString(w, `\b`)
			if err != nil {
				return err
			}
		case '\f':
			_, err := io.WriteString(w, `\f`)
			if err != nil {
				return err
			}
		case '\n':
			_, err := io.WriteString(w, `\n`)
			if err != nil {
				return err
			}
		case '\r':
			_, err := io.WriteString(w, `\r`)
			if err != nil {
				return err
			}
		case '\t':
			_, err := io.WriteString(w, `\t`)
			if err != nil {
				return err
			}
		default:
			if r < 0x20 {
				if _, err := fmt.Fprintf(w, `\u%04x`, r); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(w, "%c", r); err != nil {
					return err
				}
			}
		}
	}
	_, err := io.WriteString(w, `"`)
	return err
}

// DecodeReceipt parses a receipt into a generic map with numbers
// preserved as json.Number so canonicalization can replay them
// verbatim.
func DecodeReceipt(b []byte) (map[string]interface{}, error) {
	var raw map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}
