package conformance

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Inputs is everything a decision depends on, read from a case (section
// 14.2). An implementation uses nothing beyond them and reaches no network.
type Inputs struct {
	// Now is the evaluation time every window is judged against.
	Now      time.Time
	Evidence []byte
	// Policy is the complete policy, or nil for the section 7 default.
	Policy []byte
	// Collateral holds every artifact the appraisal may use, keyed as
	// section 8 keys collateral; a key absent here is unavailable.
	Collateral map[string]Artifact
	// NRAS holds the recorded exchange for each architecture batch; a
	// request with another nonce is unavailable.
	NRAS []Exchange
}

// Artifact is one held artifact: bytes as the source serves them, with the
// signing chain beside a signed Intel body.
type Artifact struct {
	Body         []byte
	SigningChain []byte
}

// Exchange is one recorded NRAS exchange.
type Exchange struct {
	Arch     string
	Nonce    string
	Response []byte
	JWKS     []byte
}

// Appraiser is an implementation under test. Appraise returns the section 5
// appraisal as JSON, or a *Refusal carrying the section 14.4 code the
// implementation maps its error to. Any other error means the
// implementation did not decide; the runner reports it as an error, never
// as a decision.
type Appraiser interface {
	Appraise(ctx context.Context, in *Inputs) ([]byte, error)
}

// Refusal is the decision to refuse.
type Refusal struct {
	Code   Code
	Reason string
}

func (r *Refusal) Error() string { return string(r.Code) + ": " + r.Reason }

// Outcome is what a case produced.
type Outcome int

const (
	// Pass: the decision matched.
	Pass Outcome = iota
	// Fail: the implementation decided differently.
	Fail
	// Error: the implementation, or the harness, did not decide.
	Error
)

func (o Outcome) String() string {
	switch o {
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	default:
		return "error"
	}
}

// Result is one case's outcome; Detail says why when it is not a pass.
type Result struct {
	ID      string
	Outcome Outcome
	Detail  string
}

// Report is a run of the whole corpus.
type Report struct {
	Version string
	Results []Result
}

// Passed reports whether every case passed.
func (r *Report) Passed() bool { return r.Count(Pass) == len(r.Results) }

// Count is the number of results with this outcome.
func (r *Report) Count(o Outcome) int {
	n := 0
	for _, x := range r.Results {
		if x.Outcome == o {
			n++
		}
	}
	return n
}

func (r *Report) String() string {
	var b strings.Builder
	for _, x := range r.Results {
		fmt.Fprintf(&b, "%-5s %s\n", x.Outcome, x.ID)
		if x.Detail != "" {
			for _, line := range strings.Split(x.Detail, "\n") {
				fmt.Fprintf(&b, "      %s\n", line)
			}
		}
	}
	fmt.Fprintf(&b, "corpus %s: %d of %d cases pass (%d fail, %d error)\n",
		r.Version, r.Count(Pass), len(r.Results), r.Count(Fail), r.Count(Error))
	return b.String()
}

// Inputs reads a case's inputs.
func (c *Corpus) Inputs(cs *Case) (*Inputs, error) {
	now, err := parseNow(cs.Now)
	if err != nil {
		return nil, err
	}
	in := &Inputs{Now: now, Collateral: map[string]Artifact{}}
	if in.Evidence, err = c.Read(cs.Evidence); err != nil {
		return nil, err
	}
	if cs.Policy != "" {
		if in.Policy, err = c.Read(cs.Policy); err != nil {
			return nil, err
		}
	}
	for key, r := range cs.Collateral {
		var a Artifact
		if r.Signed() {
			if a.Body, err = c.Read(r.Body); err != nil {
				return nil, err
			}
			if a.SigningChain, err = c.Read(r.SigningChain); err != nil {
				return nil, err
			}
		} else if a.Body, err = c.Read(r.Path); err != nil {
			return nil, err
		}
		in.Collateral[key] = a
	}
	for _, x := range cs.NRAS {
		e := Exchange{Arch: x.Arch, Nonce: x.Nonce}
		if e.Response, err = c.Read(x.Response); err != nil {
			return nil, err
		}
		if e.JWKS, err = c.Read(x.JWKS); err != nil {
			return nil, err
		}
		in.NRAS = append(in.NRAS, e)
	}
	return in, nil
}

// Run runs every case against a and reports each outcome. A panic in the
// implementation is an error for that case, never the end of the run.
func Run(ctx context.Context, c *Corpus, a Appraiser) *Report {
	r := &Report{Version: c.Version}
	for i := range c.Cases {
		r.Results = append(r.Results, c.run(ctx, &c.Cases[i], a))
	}
	return r
}

// Test runs every case as a subtest of t, for an implementation's own test
// suite.
func Test(t *testing.T, c *Corpus, a Appraiser) {
	t.Helper()
	for i := range c.Cases {
		cs := &c.Cases[i]
		t.Run(cs.ID, func(t *testing.T) {
			res := c.run(context.Background(), cs, a)
			if res.Outcome != Pass {
				t.Errorf("%s: %s", res.Outcome, res.Detail)
			}
		})
	}
}

func (c *Corpus) run(ctx context.Context, cs *Case, a Appraiser) Result {
	in, err := c.Inputs(cs)
	if err != nil {
		return Result{cs.ID, Error, err.Error()}
	}
	got, err := appraise(ctx, a, in)
	var refusal *Refusal
	if err != nil {
		var ok bool
		if refusal, ok = err.(*Refusal); !ok {
			return Result{cs.ID, Error, err.Error()}
		}
	}
	if cs.Expect.Refusal != "" {
		switch {
		case refusal == nil:
			return Result{cs.ID, Fail, fmt.Sprintf("appraised, expected refusal %s", cs.Expect.Refusal)}
		case refusal.Code != cs.Expect.Refusal:
			return Result{cs.ID, Fail, fmt.Sprintf("refused with %s, expected %s: %s", refusal.Code, cs.Expect.Refusal, refusal.Reason)}
		default:
			return Result{cs.ID, Pass, ""}
		}
	}
	if refusal != nil {
		return Result{cs.ID, Fail, fmt.Sprintf("refused with %s, expected an appraisal: %s", refusal.Code, refusal.Reason)}
	}
	raw, err := c.Read(cs.Expect.Appraisal)
	if err != nil {
		return Result{cs.ID, Error, err.Error()}
	}
	want, err := ParseJSON(raw)
	if err != nil {
		return Result{cs.ID, Error, fmt.Sprintf("%s: %v", cs.Expect.Appraisal, err)}
	}
	have, err := ParseJSON(got)
	if err != nil {
		return Result{cs.ID, Error, fmt.Sprintf("the appraisal is not JSON: %v", err)}
	}
	Strip(want)
	Strip(have)
	if !Equal(want, have) {
		return Result{cs.ID, Fail, fmt.Sprintf("appraisal differs from %s:\n%s", cs.Expect.Appraisal, Diff(want, have))}
	}
	return Result{cs.ID, Pass, ""}
}

func appraise(ctx context.Context, a Appraiser, in *Inputs) (out []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			out, err = nil, fmt.Errorf("the implementation panicked: %v", p)
		}
	}()
	return a.Appraise(ctx, in)
}
