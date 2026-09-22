// Package conformance holds the conformance corpus of the CVM attestation
// profile (design doc section 14) and runs it against an [Appraiser].
//
// The corpus is embedded, so a Go implementation pins a corpus version by
// pinning this module's version; [LoadDir] reads a checkout instead.
package conformance

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed VERSION cases inputs
var embedded embed.FS

// Corpus is one revision: its version and its cases, with the inputs they
// reference.
type Corpus struct {
	Version string
	Cases   []Case
	inputs  fs.FS
}

// Case is one case in the section 14.2 format. Paths are relative to the
// corpus's inputs directory and read through [Corpus.Read].
type Case struct {
	ID         string                   `json:"id"`
	Rule       Rule                     `json:"rule"`
	Now        string                   `json:"now"`
	Evidence   string                   `json:"evidence"`
	Policy     string                   `json:"policy,omitempty"`
	Collateral map[string]CollateralRef `json:"collateral,omitempty"`
	NRAS       []NrasExchange           `json:"nras,omitempty"`
	Expect     Expect                   `json:"expect"`
}

// Rule names the statement a case exercises.
type Rule struct {
	Section   string `json:"section"`
	Statement string `json:"statement"`
}

// CollateralRef is one artifact of a case: a file of bytes as the source
// serves them, or a signed Intel body with the chain that signs it.
type CollateralRef struct {
	Path         string // the bytes, when SigningChain is empty
	Body         string
	SigningChain string
}

// Signed reports whether the artifact carries a signing chain.
func (r CollateralRef) Signed() bool { return r.SigningChain != "" }

func (r *CollateralRef) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*r = CollateralRef{Path: s}
		return nil
	}
	var o struct {
		Body         string `json:"body"`
		SigningChain string `json:"signing_chain"`
	}
	if err := decodeStrict(b, &o); err != nil {
		return fmt.Errorf("collateral: a path or {body, signing_chain}: %w", err)
	}
	if o.Body == "" || o.SigningChain == "" {
		return errors.New("collateral: a signed artifact names both body and signing_chain")
	}
	*r = CollateralRef{Body: o.Body, SigningChain: o.SigningChain}
	return nil
}

func (r CollateralRef) MarshalJSON() ([]byte, error) {
	if !r.Signed() {
		return json.Marshal(r.Path)
	}
	return json.Marshal(struct {
		Body         string `json:"body"`
		SigningChain string `json:"signing_chain"`
	}{r.Body, r.SigningChain})
}

// NrasExchange is one recorded NRAS exchange: the nonce the appraisal sends
// for an architecture batch, the detached EAT it got back and the JWKS that
// verifies it.
type NrasExchange struct {
	Arch     string `json:"arch"`
	Nonce    string `json:"nonce"`
	Response string `json:"response"`
	JWKS     string `json:"jwks"`
}

// Expect is the decision the profile requires: exactly one of an appraisal
// file or a refusal code.
type Expect struct {
	Appraisal string
	Refusal   Code
}

func (e *Expect) UnmarshalJSON(b []byte) error {
	var o struct {
		Appraisal *string `json:"appraisal"`
		Refusal   *Code   `json:"refusal"`
	}
	if err := decodeStrict(b, &o); err != nil {
		return fmt.Errorf("expect: %w", err)
	}
	if (o.Appraisal == nil) == (o.Refusal == nil) {
		return errors.New("expect: exactly one of appraisal or refusal")
	}
	if o.Appraisal != nil {
		*e = Expect{Appraisal: *o.Appraisal}
	} else {
		*e = Expect{Refusal: *o.Refusal}
	}
	return nil
}

func (e Expect) MarshalJSON() ([]byte, error) {
	if e.Appraisal != "" {
		return json.Marshal(map[string]string{"appraisal": e.Appraisal})
	}
	return json.Marshal(map[string]Code{"refusal": e.Refusal})
}

var (
	idPattern      = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
)

// Load returns the corpus embedded in this module.
func Load() (*Corpus, error) { return LoadFS(embedded) }

// LoadDir loads a corpus from a checkout of the conformance directory.
func LoadDir(dir string) (*Corpus, error) { return LoadFS(os.DirFS(dir)) }

// LoadFS loads a corpus from a file system holding VERSION, cases and
// inputs. Every case is checked against the section 14.2 format and every
// input it references must exist.
func LoadFS(fsys fs.FS) (*Corpus, error) {
	raw, err := fs.ReadFile(fsys, "VERSION")
	if err != nil {
		return nil, err
	}
	version := strings.TrimSpace(string(raw))
	if !versionPattern.MatchString(version) {
		return nil, fmt.Errorf("VERSION %q is not <profile>.<revision>", version)
	}
	entries, err := fs.ReadDir(fsys, "cases")
	if err != nil {
		return nil, err
	}
	inputs, err := fs.Sub(fsys, "inputs")
	if err != nil {
		return nil, err
	}
	c := &Corpus{Version: version, inputs: inputs}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join("cases", name))
		if err != nil {
			return nil, err
		}
		var cs Case
		if err := decodeStrict(raw, &cs); err != nil {
			return nil, fmt.Errorf("cases/%s: %w", name, err)
		}
		if cs.ID != strings.TrimSuffix(name, ".json") {
			return nil, fmt.Errorf("cases/%s: a case file is named by its id, got %q", name, cs.ID)
		}
		if seen[cs.ID] {
			return nil, fmt.Errorf("cases/%s: duplicate id", name)
		}
		seen[cs.ID] = true
		if err := c.check(&cs); err != nil {
			return nil, fmt.Errorf("cases/%s: %w", name, err)
		}
		c.Cases = append(c.Cases, cs)
	}
	if len(c.Cases) == 0 {
		return nil, errors.New("no cases")
	}
	sort.Slice(c.Cases, func(i, j int) bool { return c.Cases[i].ID < c.Cases[j].ID })
	return c, nil
}

// check applies the section 14.2 rules a decoder cannot.
func (c *Corpus) check(cs *Case) error {
	if !idPattern.MatchString(cs.ID) {
		return fmt.Errorf("id %q is not kebab-case", cs.ID)
	}
	if cs.Rule.Section == "" || cs.Rule.Statement == "" {
		return errors.New("rule names a section and quotes its statement")
	}
	if _, err := parseNow(cs.Now); err != nil {
		return err
	}
	if err := c.exists(cs.Evidence); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	if cs.Policy != "" {
		if err := c.exists(cs.Policy); err != nil {
			return fmt.Errorf("policy: %w", err)
		}
	}
	for key, r := range cs.Collateral {
		if key == "" {
			return errors.New("collateral: empty key")
		}
		for _, p := range []string{r.Path, r.Body, r.SigningChain} {
			if p == "" {
				continue
			}
			if err := c.exists(p); err != nil {
				return fmt.Errorf("collateral %s: %w", key, err)
			}
		}
	}
	for i, x := range cs.NRAS {
		if x.Arch == "" || x.Nonce == "" {
			return fmt.Errorf("nras[%d]: arch and nonce are required", i)
		}
		for _, p := range []string{x.Response, x.JWKS} {
			if err := c.exists(p); err != nil {
				return fmt.Errorf("nras[%d]: %w", i, err)
			}
		}
	}
	if cs.Expect.Appraisal != "" {
		if err := c.exists(cs.Expect.Appraisal); err != nil {
			return fmt.Errorf("expect.appraisal: %w", err)
		}
	}
	return nil
}

func (c *Corpus) exists(p string) error {
	if err := checkPath(p); err != nil {
		return err
	}
	info, err := fs.Stat(c.inputs, p)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", p)
	}
	return nil
}

// checkPath admits the section 14.2 path form: relative to inputs, forward
// slashes, no parent segments.
func checkPath(p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case strings.Contains(p, `\`):
		return fmt.Errorf("%q: forward slashes only", p)
	case path.IsAbs(p) || path.Clean(p) != p:
		return fmt.Errorf("%q: a clean relative path", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return fmt.Errorf("%q: no parent segments", p)
		}
	}
	return nil
}

func parseNow(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("now: %w", err)
	}
	return t.UTC(), nil
}

// Read returns an input by its case-relative path.
func (c *Corpus) Read(p string) ([]byte, error) {
	if err := checkPath(p); err != nil {
		return nil, err
	}
	return fs.ReadFile(c.inputs, p)
}

// Case returns the case with this id.
func (c *Corpus) Case(id string) (*Case, bool) {
	for i := range c.Cases {
		if c.Cases[i].ID == id {
			return &c.Cases[i], true
		}
	}
	return nil, false
}

// decodeStrict decodes one JSON value into v, refusing unknown members and
// trailing data.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("trailing data after the value")
	}
	return nil
}
