package aerf

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// postIssuanceFields is the set stripped before computing the
// canonical payload that the issuer and parent signed (SPEC.md §7,
// §8.4 / C-24).
var postIssuanceFields = []string{
	"signature",
	"timestamp",
	"parent_signature",
	"parent_key_id",
	"log_inclusion_proof",
}

// Result is the outcome of a full verification pass.
type Result struct {
	OK           bool
	IssuerOK     bool
	ParentOK     CheckOutcome
	PDPOK        CheckOutcome
	LogOK        CheckOutcome
	HasImpact    bool
	ImpactTags   []string
	Warnings     []string
	FailReason   string
	FailCategory string
	ReceiptID    string
	Agent        string
	Action       string
	InPolicy     interface{}
	KeyID        string
}

// CheckOutcome describes the status of an optional v0.2 check.
type CheckOutcome string

const (
	CheckSkipped CheckOutcome = "skipped"
	CheckPassed  CheckOutcome = "passed"
	CheckFailed  CheckOutcome = "failed"
	CheckMissing CheckOutcome = "missing"
)

// Options controls which v0.2 checks run.
type Options struct {
	IssuerKey  ed25519.PublicKey
	ParentKey  ed25519.PublicKey // optional
	PDPKey     ed25519.PublicKey // optional
	LogKey     ed25519.PublicKey // optional
	RequireParentSig bool
	RequirePDPSig    bool
	RequireLog       bool
}

// VerifyReceipt runs the full v0.2 verification flow on a parsed
// receipt. Returns a Result that summarises every check; the boolean
// OK field is true only if every applicable check passed.
func VerifyReceipt(receipt map[string]interface{}, opt Options) *Result {
	res := &Result{
		ParentOK: CheckSkipped,
		PDPOK:    CheckSkipped,
		LogOK:    CheckSkipped,
	}
	if id, ok := receipt["id"].(string); ok {
		res.ReceiptID = id
	}
	if agent, ok := receipt["agent"].(string); ok {
		res.Agent = agent
	}
	if action, ok := receipt["action"].(string); ok {
		res.Action = action
	}
	if kid, ok := receipt["key_id"].(string); ok {
		res.KeyID = kid
	}
	res.InPolicy = receipt["in_policy"]

	tags := impactTags(receipt)
	res.HasImpact = len(tags) > 0
	res.ImpactTags = tags

	if err := verifyIssuer(receipt, opt.IssuerKey); err != nil {
		res.fail("issuer_signature", err)
		return res
	}
	res.IssuerOK = true

	if outcome, err := runParent(receipt, opt, res.HasImpact); err != nil {
		res.ParentOK = outcome
		res.fail("parent_signature", err)
		return res
	} else {
		res.ParentOK = outcome
	}

	if outcome, err := runPDP(receipt, opt, res.HasImpact); err != nil {
		res.PDPOK = outcome
		res.fail("pdp_signature", err)
		return res
	} else {
		res.PDPOK = outcome
	}

	if outcome, err := runLog(receipt, opt); err != nil {
		res.LogOK = outcome
		res.fail("log_inclusion", err)
		return res
	} else {
		res.LogOK = outcome
	}

	res.OK = true
	return res
}

func (r *Result) fail(category string, err error) {
	r.OK = false
	r.FailCategory = category
	r.FailReason = err.Error()
}

func verifyIssuer(r map[string]interface{}, pub ed25519.PublicKey) error {
	sigHex, ok := r["signature"].(string)
	if !ok {
		return errors.New("receipt missing 'signature' field")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("bad hex: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("wrong length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	canonical, err := SignedPayload(r)
	if err != nil {
		return fmt.Errorf("canonicalize: %v", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return errors.New("issuer signature verification FAILED")
	}
	return nil
}

func runParent(r map[string]interface{}, opt Options, hasImpact bool) (CheckOutcome, error) {
	_, hasSig := r["parent_signature"].(string)
	if hasImpact && !hasSig {
		return CheckMissing, errors.New("impact_tags non-empty but parent_signature absent")
	}
	if !hasSig {
		if opt.RequireParentSig {
			return CheckMissing, errors.New("--require-parent-sig set but parent_signature absent")
		}
		return CheckSkipped, nil
	}
	if opt.ParentKey == nil {
		if opt.RequireParentSig {
			return CheckMissing, errors.New("--require-parent-sig set but no parent key supplied")
		}
		return CheckSkipped, nil
	}
	if err := VerifyParent(r, opt.ParentKey); err != nil {
		return CheckFailed, err
	}
	return CheckPassed, nil
}

func runPDP(r map[string]interface{}, opt Options, hasImpact bool) (CheckOutcome, error) {
	_, hasSig := r["pdp_signature"].(string)
	if hasImpact && !hasSig {
		return CheckMissing, errors.New("impact_tags non-empty but pdp_signature absent")
	}
	if !hasSig {
		if opt.RequirePDPSig {
			return CheckMissing, errors.New("--require-pdp-sig set but pdp_signature absent")
		}
		return CheckSkipped, nil
	}
	if opt.PDPKey == nil {
		if opt.RequirePDPSig {
			return CheckMissing, errors.New("--require-pdp-sig set but no pdp key supplied")
		}
		return CheckSkipped, nil
	}
	if err := VerifyPDP(r, opt.PDPKey); err != nil {
		return CheckFailed, err
	}
	return CheckPassed, nil
}

func runLog(r map[string]interface{}, opt Options) (CheckOutcome, error) {
	_, hasProof := r["log_inclusion_proof"].(map[string]interface{})
	if !hasProof {
		if opt.RequireLog {
			return CheckMissing, errors.New("--require-log set but log_inclusion_proof absent")
		}
		return CheckSkipped, nil
	}
	if opt.LogKey == nil {
		if opt.RequireLog {
			return CheckMissing, errors.New("--require-log set but no log key supplied")
		}
		return CheckSkipped, nil
	}
	if err := VerifyLogInclusion(r, opt.LogKey); err != nil {
		return CheckFailed, err
	}
	return CheckPassed, nil
}

// SignedPayload returns the canonical bytes covered by the issuer
// signature and the parent counter-signature.
func SignedPayload(r map[string]interface{}) ([]byte, error) {
	return Canonical(stripFields(r, postIssuanceFields))
}

// stripFields returns a shallow copy of r with the named fields
// removed. The original map is untouched; this matters because
// vectors are shared across verification passes.
func stripFields(r map[string]interface{}, fields []string) map[string]interface{} {
	out := make(map[string]interface{}, len(r))
	skip := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		skip[f] = struct{}{}
	}
	for k, v := range r {
		if _, drop := skip[k]; drop {
			continue
		}
		out[k] = v
	}
	return out
}

// VerifyParent checks parent_signature against the same canonical
// payload that the issuer signed.
func VerifyParent(r map[string]interface{}, parentPub ed25519.PublicKey) error {
	sig, err := decodeEd25519Sig(r, "parent_signature")
	if err != nil {
		return err
	}
	canonical, err := SignedPayload(r)
	if err != nil {
		return fmt.Errorf("canonicalize: %v", err)
	}
	if !ed25519.Verify(parentPub, canonical, sig) {
		return errors.New("parent signature verification FAILED")
	}
	return nil
}

// VerifyPDP checks pdp_signature against the canonical JSON of the
// PDP-bound tuple (SPEC.md §17).
func VerifyPDP(r map[string]interface{}, pdpPub ed25519.PublicKey) error {
	sig, err := decodeEd25519Sig(r, "pdp_signature")
	if err != nil {
		return err
	}
	ctxHash, _ := r["context_hash_sha256"].(string)
	policyHash, _ := r["policy_hash"].(string)
	inPolicy, hasInPolicy := r["in_policy"].(bool)
	if !hasInPolicy || ctxHash == "" || policyHash == "" {
		return errors.New("pdp_signature requires context_hash_sha256, policy_hash, in_policy")
	}
	canonical, err := Canonical(map[string]interface{}{
		"context_hash_sha256": ctxHash,
		"in_policy":           inPolicy,
		"policy_hash":         policyHash,
	})
	if err != nil {
		return fmt.Errorf("canonicalize pdp tuple: %v", err)
	}
	if !ed25519.Verify(pdpPub, canonical, sig) {
		return errors.New("pdp signature verification FAILED")
	}
	return nil
}

// VerifyLogInclusion verifies the STH signature, the leaf hash
// recomputation, and the audit path against the STH root.
func VerifyLogInclusion(r map[string]interface{}, logPub ed25519.PublicKey) error {
	proof, ok := r["log_inclusion_proof"].(map[string]interface{})
	if !ok {
		return errors.New("log_inclusion_proof missing or wrong shape")
	}
	sth, ok := proof["sth"].(map[string]interface{})
	if !ok {
		return errors.New("log_inclusion_proof.sth missing")
	}
	sthSig, err := decodeEd25519Sig(proof, "sth_signature")
	if err != nil {
		return fmt.Errorf("sth_signature: %v", err)
	}
	sthCanonical, err := Canonical(sth)
	if err != nil {
		return fmt.Errorf("canonicalize sth: %v", err)
	}
	if !ed25519.Verify(logPub, sthCanonical, sthSig) {
		return errors.New("sth signature verification FAILED")
	}

	leafHashHex, _ := proof["leaf_hash"].(string)
	leafHash, err := hex.DecodeString(leafHashHex)
	if err != nil || len(leafHash) != sha256.Size {
		return errors.New("leaf_hash malformed")
	}
	expected, err := LogLeafHash(r)
	if err != nil {
		return fmt.Errorf("compute leaf hash: %v", err)
	}
	if hex.EncodeToString(expected) != leafHashHex {
		return errors.New("leaf_hash does not match recomputed receipt leaf")
	}

	path, err := decodeAuditPath(proof["audit_path"])
	if err != nil {
		return err
	}
	treeSize, err := jsonInt(proof["tree_size"])
	if err != nil {
		return fmt.Errorf("tree_size: %v", err)
	}
	leafIndex, _ := jsonInt(proof["leaf_index"])
	root := walkAuditPath(leafHash, path, leafIndex, treeSize)
	sthRootHex, _ := sth["root_hash"].(string)
	if hex.EncodeToString(root) != sthRootHex {
		return errors.New("audit_path does not lead to STH root_hash")
	}
	return nil
}

// LogLeafHash returns the RFC 6962 leaf hash of the receipt: SHA-256
// of (0x00 || canonical_payload), where canonical_payload uses the
// same strip set as the chain-hash input (SPEC.md §8.4 / §15).
func LogLeafHash(r map[string]interface{}) ([]byte, error) {
	canonical, err := SignedPayload(r)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(canonical)
	return h.Sum(nil), nil
}

func decodeEd25519Sig(r map[string]interface{}, field string) ([]byte, error) {
	hexStr, ok := r[field].(string)
	if !ok || hexStr == "" {
		return nil, fmt.Errorf("%s missing", field)
	}
	sig, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%s bad hex: %v", field, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%s wrong length: got %d, want %d", field, len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

func decodeAuditPath(v interface{}) ([][]byte, error) {
	arr, _ := v.([]interface{})
	out := make([][]byte, 0, len(arr))
	for i, step := range arr {
		s, ok := step.(string)
		if !ok {
			return nil, fmt.Errorf("audit_path[%d] not a string", i)
		}
		h, err := hex.DecodeString(s)
		if err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("audit_path[%d] malformed", i)
		}
		out = append(out, h)
	}
	return out, nil
}

func jsonInt(v interface{}) (int64, error) {
	if v == nil {
		return 0, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("expected JSON number, got %T", v)
	}
	return n.Int64()
}

// walkAuditPath computes the root from a leaf hash and an RFC 6962
// audit path. The sibling sits left of the current node when the
// current index is odd; the last node at an odd-sized level is
// promoted without combining.
func walkAuditPath(leafHash []byte, path [][]byte, leafIndex, treeSize int64) []byte {
	node := leafHash
	idx := leafIndex
	last := treeSize - 1
	for _, sibling := range path {
		if idx == last && idx%2 == 0 {
			idx /= 2
			last /= 2
			continue
		}
		if idx%2 == 1 {
			node = hashInternal(sibling, node)
		} else {
			node = hashInternal(node, sibling)
		}
		idx /= 2
		last /= 2
	}
	return node
}

func hashInternal(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func impactTags(r map[string]interface{}) []string {
	tags, ok := r["impact_tags"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if s, ok := t.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
