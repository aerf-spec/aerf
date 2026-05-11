// aerf-render produces a self-contained HTML view of an AERF receipt
// verification result. The output is one file with no external assets
// (no JavaScript, no remote fonts, no images) so it can be embedded
// in a static site or served directly.
//
// Usage:
//
//	aerf-render <receipt.json> <issuer_key.pem> [flags] > report.html
//
// Flags mirror aerf-verify (--parent-key, --pdp-key, --log-key,
// --require-parent-sig, --require-pdp-sig, --require-log). With no
// optional keys, the renderer shows v0.1-compatible verification.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/aerf-spec/aerf/verifiers/go/internal/aerf"
)

const usage = `usage: aerf-render <receipt.json> <issuer_key.pem> [flags]

  --parent-key PEM        verify parent_signature against this key
  --pdp-key PEM           verify pdp_signature against this key
  --log-key PEM           verify log_inclusion_proof against this key
  --require-parent-sig    fail when parent check cannot run
  --require-pdp-sig       fail when PDP check cannot run
  --require-log           fail when log check cannot run
  --title STRING          override the HTML title (default: AERF Receipt)
  --output PATH           write to file instead of stdout`

type view struct {
	Title       string
	GeneratedAt string
	OK          bool
	OutcomeWord string
	OutcomeCSS  string
	FailReason  string
	FailCat     string
	Receipt     *aerf.Result
	HasImpact   bool
	ImpactTags  string
}

func main() {
	parentKey := flag.String("parent-key", "", "PEM for parent public key")
	pdpKey := flag.String("pdp-key", "", "PEM for PDP public key")
	logKey := flag.String("log-key", "", "PEM for log STH-signing key")
	requireParent := flag.Bool("require-parent-sig", false, "")
	requirePDP := flag.Bool("require-pdp-sig", false, "")
	requireLog := flag.Bool("require-log", false, "")
	title := flag.String("title", "AERF Receipt", "HTML title")
	output := flag.String("output", "", "write report to file (default stdout)")
	flag.Usage = func() { fmt.Fprintln(os.Stderr, usage) }
	flag.Parse()

	if flag.NArg() != 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	receiptBytes, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		die("read receipt: %v", err)
	}
	issuer, err := aerf.LoadPublicKeyFile(flag.Arg(1))
	if err != nil {
		die("parse issuer key: %v", err)
	}
	receipt, err := aerf.DecodeReceipt(receiptBytes)
	if err != nil {
		die("parse receipt: %v", err)
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

	v := view{
		Title:       *title,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		OK:          res.OK,
		Receipt:     res,
		HasImpact:   res.HasImpact,
		ImpactTags:  strings.Join(res.ImpactTags, ", "),
		FailReason:  res.FailReason,
		FailCat:     res.FailCategory,
	}
	if res.OK {
		v.OutcomeWord = "VERIFIED"
		v.OutcomeCSS = "ok"
	} else {
		v.OutcomeWord = "FAILED"
		v.OutcomeCSS = "fail"
	}

	w := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			die("open output: %v", err)
		}
		defer f.Close()
		w = f
	}
	if err := page.Execute(w, v); err != nil {
		die("render: %v", err)
	}
	if !res.OK {
		os.Exit(1)
	}
}

func loadOptKey(role, path string) ed25519.PublicKey {
	if path == "" {
		return nil
	}
	k, err := aerf.LoadPublicKeyFile(path)
	if err != nil {
		die("parse %s key: %v", role, err)
	}
	return k
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(2)
}

var page *template.Template

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  :root {
    --ok: #1f7a3a;
    --fail: #b3261e;
    --skip: #6b6b6b;
    --bg: #fafafa;
    --card: #ffffff;
    --line: #e3e3e3;
    --text: #1a1a1a;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  body {
    margin: 0;
    padding: 2rem 1rem;
    background: var(--bg);
    color: var(--text);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    line-height: 1.5;
  }
  .wrap { max-width: 720px; margin: 0 auto; }
  h1 { margin: 0 0 .25rem; font-size: 1.4rem; }
  .meta { color: #555; font-size: .85rem; margin-bottom: 1.5rem; }
  .card {
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
  }
  .badge {
    display: inline-block;
    padding: .15rem .6rem;
    border-radius: 999px;
    font-weight: 600;
    font-size: .8rem;
    letter-spacing: .04em;
  }
  .badge.ok   { background: #e6f4ea; color: var(--ok); }
  .badge.fail { background: #fce8e6; color: var(--fail); }
  .badge.skip { background: #f0f0f0; color: var(--skip); }
  dl { margin: .75rem 0 0; display: grid; grid-template-columns: 9.5rem 1fr; gap: .4rem 1rem; }
  dt { color: #555; font-size: .85rem; }
  dd { margin: 0; font-family: var(--mono); font-size: .9rem; word-break: break-all; }
  .checks li { display: flex; justify-content: space-between; padding: .5rem 0; border-top: 1px solid var(--line); }
  .checks li:first-child { border-top: 0; }
  .checks ul { padding: 0; list-style: none; }
  .err {
    background: #fff5f4;
    border-left: 3px solid var(--fail);
    padding: .75rem 1rem;
    font-family: var(--mono);
    font-size: .85rem;
    margin: 0;
    white-space: pre-wrap;
  }
  footer { color: #888; font-size: .8rem; text-align: center; margin-top: 2rem; }
  a { color: inherit; }
</style>
</head>
<body>
<div class="wrap">
  <h1>{{.Title}}</h1>
  <div class="meta">Verified at {{.GeneratedAt}} by aerf-render (AERF v0.2.0-draft.1)</div>

  <div class="card">
    <span class="badge {{.OutcomeCSS}}">{{.OutcomeWord}}</span>
    {{- if not .OK }}
    <pre class="err">{{.FailCat}}: {{.FailReason}}</pre>
    {{- end }}
  </div>

  <div class="card">
    <dl>
      <dt>Receipt ID</dt><dd>{{.Receipt.ReceiptID}}</dd>
      <dt>Agent</dt><dd>{{.Receipt.Agent}}</dd>
      <dt>Action</dt><dd>{{.Receipt.Action}}</dd>
      <dt>In policy</dt><dd>{{.Receipt.InPolicy}}</dd>
      <dt>Issuer key ID</dt><dd>{{.Receipt.KeyID}}</dd>
      {{- if .HasImpact }}
      <dt>Impact tags</dt><dd>{{.ImpactTags}}</dd>
      {{- end }}
    </dl>
  </div>

  <div class="card checks">
    <h2 style="margin:0 0 .5rem; font-size:1rem;">Checks</h2>
    <ul>
      <li><span>Issuer signature</span><span class="badge {{if .Receipt.IssuerOK}}ok{{else}}fail{{end}}">{{if .Receipt.IssuerOK}}passed{{else}}failed{{end}}</span></li>
      <li><span>Parent counter-signature</span><span class="badge {{checkClass .Receipt.ParentOK}}">{{.Receipt.ParentOK}}</span></li>
      <li><span>PDP signature</span><span class="badge {{checkClass .Receipt.PDPOK}}">{{.Receipt.PDPOK}}</span></li>
      <li><span>Log inclusion proof</span><span class="badge {{checkClass .Receipt.LogOK}}">{{.Receipt.LogOK}}</span></li>
    </ul>
  </div>

  <footer>
    aerf-render &middot; <a href="https://github.com/aerf-spec/aerf">github.com/aerf-spec/aerf</a>
  </footer>
</div>
</body>
</html>
`

func init() {
	page = template.Must(template.New("page").Funcs(template.FuncMap{
		"checkClass": func(c aerf.CheckOutcome) string {
			switch c {
			case aerf.CheckPassed:
				return "ok"
			case aerf.CheckFailed, aerf.CheckMissing:
				return "fail"
			default:
				return "skip"
			}
		},
	}).Parse(htmlTemplate))
}
