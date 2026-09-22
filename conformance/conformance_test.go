package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// replay answers every case with its own expectation: the harness must pass
// the whole corpus through it, which proves the plumbing end to end.
type replay struct{ c *Corpus }

func (r replay) Appraise(_ context.Context, in *Inputs) ([]byte, error) {
	for i := range r.c.Cases {
		cs := &r.c.Cases[i]
		want, err := r.c.Inputs(cs)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(in, want) {
			continue
		}
		if cs.Expect.Refusal != "" {
			return nil, &Refusal{Code: cs.Expect.Refusal, Reason: "replayed"}
		}
		return r.c.Read(cs.Expect.Appraisal)
	}
	return nil, errors.New("no case has these inputs")
}

type refuseAll struct{ code Code }

func (r refuseAll) Appraise(context.Context, *Inputs) ([]byte, error) {
	return nil, &Refusal{Code: r.code, Reason: "always"}
}

type broken struct{}

func (broken) Appraise(context.Context, *Inputs) ([]byte, error) {
	return nil, errors.New("the network is unreachable")
}

type panics struct{}

func (panics) Appraise(context.Context, *Inputs) ([]byte, error) { panic("index out of range") }

func load(t *testing.T) *Corpus {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCorpusLoads(t *testing.T) {
	c := load(t)
	if c.Version == "" || len(c.Cases) == 0 {
		t.Fatalf("version %q, %d cases", c.Version, len(c.Cases))
	}
	appraisals, refusals := 0, 0
	for i := range c.Cases {
		cs := &c.Cases[i]
		in, err := c.Inputs(cs)
		if err != nil {
			t.Fatalf("%s: %v", cs.ID, err)
		}
		if len(in.Evidence) == 0 || in.Now.IsZero() {
			t.Fatalf("%s: inputs incomplete", cs.ID)
		}
		if len(in.Collateral) != len(cs.Collateral) {
			t.Fatalf("%s: %d artifacts read for %d references", cs.ID, len(in.Collateral), len(cs.Collateral))
		}
		if cs.Expect.Appraisal != "" {
			appraisals++
		} else {
			refusals++
		}
	}
	if appraisals == 0 || refusals == 0 {
		t.Fatalf("%d appraisal and %d refusal cases; the corpus shows both decisions", appraisals, refusals)
	}
	if _, ok := c.Case(c.Cases[0].ID); !ok {
		t.Fatal("Case lookup")
	}
}

func TestReplayPassesEveryCase(t *testing.T) {
	c := load(t)
	Test(t, c, replay{c})
	r := Run(context.Background(), c, replay{c})
	if !r.Passed() || len(r.Results) != len(c.Cases) {
		t.Fatalf("replay: %s", r)
	}
	if !strings.Contains(r.String(), "corpus "+c.Version+": ") {
		t.Fatalf("report names the corpus version: %s", r)
	}
}

func TestAnotherDecisionFails(t *testing.T) {
	c := load(t)
	r := Run(context.Background(), c, refuseAll{PolicyInvalid})
	for _, res := range r.Results {
		cs, _ := c.Case(res.ID)
		want := Fail
		if cs.Expect.Refusal == PolicyInvalid {
			want = Pass
		}
		if res.Outcome != want {
			t.Errorf("%s: %s, expected %s: %s", res.ID, res.Outcome, want, res.Detail)
		}
	}
	if r.Passed() {
		t.Fatal("a refusal where an appraisal is expected is a failure")
	}
}

func TestNotDecidingIsAnError(t *testing.T) {
	c := load(t)
	for _, a := range []Appraiser{broken{}, panics{}} {
		r := Run(context.Background(), c, a)
		if r.Count(Error) != len(c.Cases) {
			t.Fatalf("%T: %s", a, r)
		}
	}
}

func TestEqualNumbersByValue(t *testing.T) {
	same := [][2]string{{"1", "1.0"}, {"1", "1e0"}, {"-0", "0"}, {"1.5", "15e-1"}, {"9007199254740993", "9007199254740993"}}
	for _, p := range same {
		a, b := json.Number(p[0]), json.Number(p[1])
		if !Equal(a, b) {
			t.Errorf("%s and %s are the same number", a, b)
		}
	}
	differ := [][2]string{{"1", "2"}, {"9007199254740993", "9007199254740992"}, {"0.1", "0.10000000000000001"}}
	for _, p := range differ {
		a, b := json.Number(p[0]), json.Number(p[1])
		if Equal(a, b) {
			t.Errorf("%s and %s differ", a, b)
		}
	}
	if Equal(json.Number("1"), "1") || Equal(json.Number("1"), true) {
		t.Error("a number equals no other kind")
	}
}

func TestEqualStructure(t *testing.T) {
	a, _ := ParseJSON([]byte(`{"a":[1,{"b":null}],"c":"x"}`))
	b, _ := ParseJSON([]byte(`{"c":"x","a":[1.0,{"b":null}]}`))
	if !Equal(a, b) {
		t.Fatal("member order is not part of the value")
	}
	for _, other := range []string{`{"a":[1,{"b":null}],"c":"x","d":1}`, `{"a":[1,{"b":0}],"c":"x"}`, `{"a":[1],"c":"x"}`, `[]`} {
		v, _ := ParseJSON([]byte(other))
		if Equal(a, v) {
			t.Errorf("%s differs", other)
		}
	}
}

func TestStripRemovesOnlyTheImplementationsOwn(t *testing.T) {
	v, _ := ParseJSON([]byte(`{
	  "iat": 1, "ear_verifier_id": {"build": "x"}, "ear_raw_evidence": "e", "eat_nonce": "n",
	  "submods": {"cpu": {"ear_status": "affirming", "ear_verifier_claims": {"cvm_collateral": {
	    "snp_crl/Genoa": {"status": "checked", "reason": "fresh", "signed": true}}}}}}`))
	Strip(v)
	want, _ := ParseJSON([]byte(`{"eat_nonce": "n",
	  "submods": {"cpu": {"ear_status": "affirming", "ear_verifier_claims": {"cvm_collateral": {
	    "snp_crl/Genoa": {"status": "checked", "signed": true}}}}}}`))
	if !Equal(v, want) {
		t.Fatalf("stripped: %s", Diff(want, v))
	}
	Strip("not an object")
}

func TestDiffNamesPointers(t *testing.T) {
	want, _ := ParseJSON([]byte(`{"a":{"b":1,"c":2},"d":[1,2],"e/f":1}`))
	got, _ := ParseJSON([]byte(`{"a":{"b":1,"x":2},"d":[1,3],"e/f":2}`))
	d := Diff(want, got)
	for _, line := range []string{"/a/c: missing", "/a/x: unexpected", "/d: expected [1,2], got [1,3]", "/e~1f: expected 1, got 2"} {
		if !strings.Contains(d, line) {
			t.Errorf("diff lacks %q:\n%s", line, d)
		}
	}
	if Diff(want, want) != "" {
		t.Error("equal values have no diff")
	}
}

func TestCaseFormatIsStrict(t *testing.T) {
	good := `{"id":"x-1","rule":{"section":"6","statement":"s"},"now":"2026-01-01T00:00:00Z","evidence":"e.json","expect":{"refusal":"revoked"}}`
	var cs Case
	if err := decodeStrict([]byte(good), &cs); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"unknown member":         `{"id":"x","rule":{"section":"6","statement":"s"},"now":"n","evidence":"e","expect":{"refusal":"revoked"},"extra":1}`,
		"both decisions":         `{"id":"x","rule":{"section":"6","statement":"s"},"now":"n","evidence":"e","expect":{"refusal":"revoked","appraisal":"a"}}`,
		"no decision":            `{"id":"x","rule":{"section":"6","statement":"s"},"now":"n","evidence":"e","expect":{}}`,
		"unknown code":           `{"id":"x","rule":{"section":"6","statement":"s"},"now":"n","evidence":"e","expect":{"refusal":"nope"}}`,
		"half a signed artifact": `{"id":"x","rule":{"section":"6","statement":"s"},"now":"n","evidence":"e","collateral":{"k":{"body":"b"}},"expect":{"refusal":"revoked"}}`,
		"trailing data":          good + ` {}`,
	}
	for name, text := range bad {
		if err := decodeStrict([]byte(text), new(Case)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, p := range []string{"", "/abs", "a/../b", "./a", "a\\b", "a//b", "a/"} {
		if checkPath(p) == nil {
			t.Errorf("path %q: accepted", p)
		}
	}
	if err := checkPath("evidence/x.json"); err != nil {
		t.Error(err)
	}
}

func TestCodesAreTheTable(t *testing.T) {
	if len(Codes) != 24 {
		t.Fatalf("%d codes, section 14.4 has 24", len(Codes))
	}
	seen := map[Code]bool{}
	for _, c := range Codes {
		if seen[c] || !c.Valid() {
			t.Errorf("%s", c)
		}
		seen[c] = true
	}
	if Code("").Valid() || Code("Revoked").Valid() {
		t.Error("codes are exact")
	}
}

func TestLoadDirMatchesEmbedded(t *testing.T) {
	a := load(t)
	b, err := LoadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != b.Version || len(a.Cases) != len(b.Cases) {
		t.Fatalf("embedded %s/%d, directory %s/%d", a.Version, len(a.Cases), b.Version, len(b.Cases))
	}
	for i := range a.Cases {
		x, _ := json.Marshal(a.Cases[i])
		y, _ := json.Marshal(b.Cases[i])
		if string(x) != string(y) {
			t.Fatalf("%s differs between embedded and directory", a.Cases[i].ID)
		}
	}
}
