// aerf-verify verifies an AERF-EVIDENCE receipt against an Ed25519
// issuer public key, with optional v0.2 parent, PDP, and log checks.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/aerf-spec/aerf/verifiers/go/internal/aerf"
)

const usage = `usage: aerf-verify [flags] <receipt.json> <issuer_key.pem>

  --parent-key PEM        verify parent_signature against this key
  --pdp-key PEM           verify pdp_signature against this key
  --log-key PEM           verify log_inclusion_proof against this key
  --require-parent-sig    fail when parent check cannot run
  --require-pdp-sig       fail when PDP check cannot run
  --require-log           fail when log check cannot run
  --json                  emit a JSON report on stdout`

func main() {
	parentKey := flag.String("parent-key", "", "PEM for parent public key")
	pdpKey := flag.String("pdp-key", "", "PEM for PDP public key")
	logKey := flag.String("log-key", "", "PEM for log STH-signing key")
	requireParent := flag.Bool("require-parent-sig", false, "fail when parent check cannot run")
	requirePDP := flag.Bool("require-pdp-sig", false, "fail when PDP check cannot run")
	requireLog := flag.Bool("require-log", false, "fail when log check cannot run")
	jsonOut := flag.Bool("json", false, "emit a JSON report on stdout")
	flag.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	flag.Parse()

	if flag.NArg() != 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	receiptBytes, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		die(2, "read receipt: %v", err)
	}

	issuer, err := aerf.LoadPublicKeyFile(flag.Arg(1))
	if err != nil {
		die(2, "parse issuer key: %v", err)
	}

	receipt, err := aerf.DecodeReceipt(receiptBytes)
	if err != nil {
		die(2, "parse receipt: %v", err)
	}

	opt := aerf.Options{
		IssuerKey:        issuer,
		ParentKey:        loadOptKey("parent", *parentKey),
		PDPKey:           loadOptKey("pdp", *pdpKey),
		LogKey:           loadOptKey("log", *logKey),
		RequireParentSig: *requireParent,
		RequirePDPSig:    *requirePDP,
		RequireLog:       *requireLog,
	}

	res := aerf.VerifyReceipt(receipt, opt)
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
			die(2, "encode json: %v", err)
		}
	} else if res.OK {
		printHuman(res)
	} else {
		fmt.Fprintf(os.Stderr, "FAIL %s %s\n", res.FailCategory, res.FailReason)
	}

	if !res.OK {
		os.Exit(1)
	}
}

func loadOptKey(role, path string) ed25519.PublicKey {
	if path == "" {
		return nil
	}
	key, err := aerf.LoadPublicKeyFile(path)
	if err != nil {
		die(2, "parse %s key: %v", role, err)
	}
	return key
}

func printHuman(res *aerf.Result) {
	fmt.Printf("OK  receipt %s\n", shortID(res.ReceiptID))
	fmt.Printf("    agent:     %s\n", res.Agent)
	fmt.Printf("    action:    %s\n", res.Action)
	fmt.Printf("    in_policy: %v\n", res.InPolicy)
	fmt.Printf("    key_id:    %s\n", res.KeyID)
	fmt.Printf("    parent:    %s\n", res.ParentOK)
	fmt.Printf("    pdp:       %s\n", res.PDPOK)
	fmt.Printf("    log:       %s\n", res.LogOK)
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	if id == "" {
		return "<unknown>"
	}
	return id
}

func die(code int, format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(code)
}
