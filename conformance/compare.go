package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
)

// ParseJSON parses one JSON value, keeping numbers exact as [json.Number].
func ParseJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, errors.New("trailing data after the value")
	}
	return v, nil
}

// Strip removes, in place, the members of section 14.3 that are the
// implementation's own and never part of the decision.
func Strip(v any) {
	o, ok := v.(map[string]any)
	if !ok {
		return
	}
	delete(o, "iat")
	delete(o, "ear_verifier_id")
	delete(o, "ear_raw_evidence")
	submods, _ := o["submods"].(map[string]any)
	for _, sub := range submods {
		s, _ := sub.(map[string]any)
		claims, _ := s["ear_verifier_claims"].(map[string]any)
		checks, _ := claims["cvm_collateral"].(map[string]any)
		for _, check := range checks {
			if c, ok := check.(map[string]any); ok {
				delete(c, "reason")
			}
		}
	}
}

// Equal reports whether two parsed JSON values are the same value: objects
// member by member, arrays position by position, numbers by value.
func Equal(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !Equal(xv, yv) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !Equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case json.Number:
		y, ok := b.(json.Number)
		return ok && numberEqual(x, y)
	default:
		return a == b
	}
}

func numberEqual(a, b json.Number) bool {
	x, okx := new(big.Rat).SetString(string(a))
	y, oky := new(big.Rat).SetString(string(b))
	if !okx || !oky {
		return a == b
	}
	return x.Cmp(y) == 0
}

// Diff lists the JSON pointers at which want and got differ, one per line,
// and is empty when they are equal.
func Diff(want, got any) string {
	var out []string
	walk("", want, got, &out)
	return strings.Join(out, "\n")
}

func walk(p string, a, b any, out *[]string) {
	x, xok := a.(map[string]any)
	y, yok := b.(map[string]any)
	if xok && yok {
		keys := map[string]bool{}
		for k := range x {
			keys[k] = true
		}
		for k := range y {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			xv, inX := x[k]
			yv, inY := y[k]
			switch {
			case inX && inY:
				walk(p+"/"+escape(k), xv, yv, out)
			case inX:
				*out = append(*out, p+"/"+escape(k)+": missing")
			default:
				*out = append(*out, p+"/"+escape(k)+": unexpected")
			}
		}
		return
	}
	if !Equal(a, b) {
		*out = append(*out, fmt.Sprintf("%s: expected %s, got %s", p, render(a), render(b)))
	}
}

func escape(k string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(k)
}

func render(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
