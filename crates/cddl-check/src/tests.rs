use crate::Module;
use serde_json::{json, Value};

const PROFILE: &str = include_str!("../../../schemas/cvm-profile-v1.cddl");

fn module(text: &str) -> Module {
    Module::parse(text).unwrap_or_else(|e| panic!("{e}"))
}

fn ok(m: &Module, v: Value) -> bool {
    m.validate("root", &v, &["json"]).unwrap()
}

#[test]
fn the_profile_module_loads() {
    let m = module(PROFILE);
    for root in ["cvm-evidence", "cvm-appraisal", "cvm-policy"] {
        m.validate(root, &json!({}), &["json"]).unwrap();
    }
}

/// The samples checked against the CDDL reference tool (the `cddl` gem
/// 0.12.14) when this crate was written: the same module, the same verdicts.
#[test]
fn agrees_with_the_reference_tool_on_its_samples() {
    let m = module(
        r#"
root = {
  profile-label ^ => "tag:confidential.ai,2026:cvm#1"
  nonce-label ^ => JC<text .b64u (bytes .size (16..64)), bytes .size (16..64)>
  version-label ^ => 1
  ? dbg-label ^ => debug-status-type
  ? tv-label ^ => tv
  * (text .feature "json") => any
}
tv = non-empty<{
  ? JC<"hardware", 4> => -128..127
  ? JC<"executables", 2> => -128..127
}>
non-empty<M> = M .within ({+ any => any})
debug-status-type = JC<"enabled", 0> / JC<"disabled", 1>
profile-label = JC<"eat_profile", 265>
nonce-label = JC<"eat_nonce", 10>
version-label = JC<"cvm_version", -70000>
dbg-label = JC<"dbgstat", 263>
tv-label = JC<"tv", 1001>
JSON-ONLY<J> = J .feature "json"
CBOR-ONLY<C> = C .feature "cbor"
JC<J, C> = JSON-ONLY<J> / CBOR-ONLY<C>
"#,
    );
    let base = || json!({"eat_profile": "tag:confidential.ai,2026:cvm#1", "eat_nonce": "AAECAwQFBgcICQoLDA0ODw", "cvm_version": 1});
    let with = |f: &dyn Fn(&mut Value)| {
        let mut v = base();
        f(&mut v);
        v
    };
    let accepted = [
        base(),
        with(&|v| v["x-unknown"] = json!([1, 2])),
        with(&|v| {
            v["dbgstat"] = json!("disabled");
            v["tv"] = json!({"hardware": 2});
        }),
    ];
    for v in accepted {
        assert!(ok(&m, v.clone()), "{v}");
    }
    let refused = [
        with(&|v| v["cvm_version"] = json!(2)),
        with(&|v| v["eat_nonce"] = json!("AAECAwQFBgcICQoLDA0ODw==")),
        with(&|v| v["eat_nonce"] = json!("AAECAwQFBgcICQoLDA0ODx")),
        with(&|v| v["eat_nonce"] = json!("AAECAwQFBgcICQoLDA0O")),
        with(&|v| v["dbgstat"] = json!(0)),
        with(&|v| v["tv"] = json!({})),
        with(&|v| v["dbgstat"] = json!("nope")),
        with(&|v| {
            v.as_object_mut().unwrap().remove("cvm_version");
        }),
        with(&|v| v["tv"] = json!({"hardware": 200})),
        with(&|v| v["tv"] = json!({"hardware": 2, "bogus": 1})),
    ];
    for v in refused {
        assert!(!ok(&m, v.clone()), "{v}");
    }
}

#[test]
fn prelude_and_literals() {
    let m = module(r#"root = [uint, int, nint, text, bool, true, null, float, 7, "x", any]"#);
    assert!(ok(
        &m,
        json!([0, -1, -2, "t", false, true, null, 1.5, 7, "x", {}])
    ));
    assert!(
        !ok(
            &m,
            json!([-1, -1, -2, "t", false, true, null, 1.5, 7, "x", {}])
        ),
        "uint"
    );
    assert!(
        !ok(
            &m,
            json!([0, -1, 0, "t", false, true, null, 1.5, 7, "x", {}])
        ),
        "nint"
    );
    assert!(
        !ok(
            &m,
            json!([0, -1, -2, "t", false, true, null, 1, 7, "x", {}])
        ),
        "float"
    );
    assert!(
        !ok(
            &m,
            json!([0, -1, -2, "t", false, true, null, 1.5, 7.0, "x", {}])
        ),
        "7.0 is no integer"
    );
    assert!(
        !ok(
            &m,
            json!([0, -1, -2, "t", false, false, null, 1.5, 7, "x", {}])
        ),
        "true"
    );
    let big = module("root = uint");
    assert!(ok(&big, json!(u64::MAX)));
    assert!(!ok(&big, json!(1.0)));
}

#[test]
fn ranges_and_comparisons() {
    let m =
        module("root = [0..3, -128..127, 1...4, uint .le 255, uint .ge 1, uint .lt 0, int .ne 5]");
    assert!(
        !ok(&m, json!([3, -128, 3, 255, 1, 0, 4])),
        "uint .lt 0 matches nothing"
    );
    let m = module("root = [0..3, -128..127, 1...4, uint .le 255, uint .ge 1, int .ne 5]");
    assert!(ok(&m, json!([3, -128, 3, 255, 1, 4])));
    for bad in [
        json!([4, 0, 1, 0, 1, 0]),
        json!([0, 128, 1, 0, 1, 0]),
        json!([0, 0, 4, 0, 1, 0]),
        json!([0, 0, 1, 256, 1, 0]),
        json!([0, 0, 1, 0, 0, 0]),
        json!([0, 0, 1, 0, 1, 5]),
    ] {
        assert!(!ok(&m, bad.clone()), "{bad}");
    }
}

#[test]
fn maps_cuts_and_occurrences() {
    let m = module(r#"root = { "a" ^ => uint, ? "b" => text, * text => any }"#);
    assert!(ok(&m, json!({"a": 1})));
    assert!(ok(&m, json!({"a": 1, "b": "x", "c": [1]})));
    assert!(
        !ok(&m, json!({"a": "x"})),
        "the cut makes a wrong value fatal"
    );
    assert!(
        ok(&m, json!({"a": 1, "b": 2})),
        "without a cut the wildcard takes it"
    );
    assert!(!ok(&m, json!({"b": "x"})), "a is required");
    let closed = module(r#"root = { "a" => uint, ? "b" => text }"#);
    assert!(
        !ok(&closed, json!({"a": 1, "c": 1})),
        "a map without a wildcard is closed"
    );
    let bounded = module("root = { 1*2 text => uint }");
    assert!(!ok(&bounded, json!({})));
    assert!(ok(&bounded, json!({"a": 1, "b": 2})));
    assert!(!ok(&bounded, json!({"a": 1, "b": 2, "c": 3})));
    let bare = module("root = { a: uint }");
    assert!(ok(&bare, json!({"a": 1})));
    assert!(!ok(&bare, json!({"a": -1})));
}

#[test]
fn groups_and_group_choices() {
    let m = module(
        r#"
root = { "t" ^ => "x", choice, * extra }
choice = ( "r" ^ => uint, ? "l" ^ => text // ? "r" ^ => none, ? "l" ^ => none )
none = uint .lt 0
extra = ( text => any )
"#,
    );
    assert!(ok(&m, json!({"t": "x", "r": 1, "l": "y"})));
    assert!(ok(&m, json!({"t": "x", "r": 1})));
    assert!(ok(&m, json!({"t": "x"})));
    assert!(!ok(&m, json!({"t": "x", "l": "y"})), "l needs r");
    assert!(
        !ok(&m, json!({"t": "x", "r": "bad"})),
        "the cut holds in every alternative"
    );
    assert!(ok(&m, json!({"t": "x", "z": 1})));
}

#[test]
fn arrays() {
    let m = module(r#"root = [ text, uint, ? 1 / 2 ]"#);
    assert!(ok(&m, json!(["a", 1])));
    assert!(ok(&m, json!(["a", 1, 2])));
    assert!(!ok(&m, json!(["a", 1, 3])));
    assert!(!ok(&m, json!(["a"])));
    assert!(!ok(&m, json!(["a", 1, 1, 1])));
    let n = module("root = [2*3 uint, * text]");
    assert!(ok(&n, json!([1, 2])));
    assert!(ok(&n, json!([1, 2, 3, "a", "b"])));
    assert!(!ok(&n, json!([1])));
    assert!(!ok(&n, json!([1, 2, 3, 4])));
    let backtrack = module("root = [* uint, 5]");
    assert!(
        ok(&backtrack, json!([1, 2, 5])),
        "the run gives back its last item"
    );
    let labels = module("root = [type: text, value: uint]");
    assert!(ok(&labels, json!(["a", 1])));
}

#[test]
fn generics_and_features() {
    let m = module(
        r#"
root = { JC<"k", 1> ^ => pair<uint, text> }
pair<A, B> = [A, B]
JSON-ONLY<J> = J .feature "json"
CBOR-ONLY<C> = C .feature "cbor"
JC<J, C> = JSON-ONLY<J> / CBOR-ONLY<C>
"#,
    );
    assert!(ok(&m, json!({"k": [1, "a"]})));
    assert!(!ok(&m, json!({"k": ["a", 1]})));
    assert!(
        !m.validate("root", &json!({"k": [1, "a"]}), &["cbor"])
            .unwrap(),
        "no cbor key in JSON"
    );
}

#[test]
fn text_controls() {
    let m = module(
        r#"root = [text .size (1..3), text .regexp "[a-f]{2}", text .regexp "a|b", text .size 2]"#,
    );
    assert!(
        ok(&m, json!(["é", "ab", "b", "xy"])),
        ".size counts UTF-8 bytes: é is 2"
    );
    assert!(!ok(&m, json!(["", "ab", "a", "xy"])));
    assert!(!ok(&m, json!(["abcd", "ab", "a", "xy"])));
    assert!(
        !ok(&m, json!(["a", "abc", "a", "xy"])),
        "a regexp matches the whole text"
    );
    assert!(!ok(&m, json!(["a", "xab", "a", "xy"])));
    assert!(
        !ok(&m, json!(["a", "ab", "ab", "xy"])),
        "alternation is anchored as a whole"
    );
    let dots = module(r#"root = text .regexp "a.c""#);
    assert!(ok(&dots, json!("abc")));
    assert!(!ok(&dots, json!("a\nc")), "XSD's . excludes line ends");
    let literal = module(r#"root = text .regexp "a^b$""#);
    assert!(
        ok(&literal, json!("a^b$")),
        "^ and $ are plain characters in XSD"
    );
}

#[test]
fn b64u_is_strict() {
    let m = module("root = text .b64u (bytes .size 2)");
    assert!(ok(&m, json!("AAE")));
    assert!(!ok(&m, json!("AAE=")), "no padding");
    assert!(!ok(&m, json!("AAF")), "zero trailing bits");
    assert!(!ok(&m, json!("AA")), "one byte");
    let alphabet = module("root = text .b64u bytes");
    assert!(ok(&alphabet, json!("-_8")));
    assert!(
        !ok(&alphabet, json!("+/8")),
        "the standard alphabet is refused"
    );
    assert!(ok(&alphabet, json!("")));
    assert!(
        !ok(&module("root = bytes"), json!("AAE")),
        "JSON has no byte strings"
    );
}

#[test]
fn base10_is_canonical() {
    let m = module("root = { + text .base10 (0..23) => bool }");
    assert!(ok(&m, json!({"0": true, "23": false})));
    assert!(!ok(&m, json!({"24": true})));
    assert!(!ok(&m, json!({"08": true})), "no leading zeros");
    assert!(!ok(&m, json!({"-0": true})));
    assert!(!ok(&m, json!({"+1": true})));
    assert!(!ok(&m, json!({"1.0": true})));
}

#[test]
fn within_default_and_unwrap() {
    let m = module(
        r#"
root = [ ne<{ ? "a" => uint }>, uint .default 3, ~t ]
ne<M> = M .within ({+ any => any})
t = #6.1(int)
"#,
    );
    assert!(ok(&m, json!([{"a": 1}, 3, -5])));
    assert!(!ok(&m, json!([{}, 3, -5])), "within: the map is not empty");
    assert!(!ok(&m, json!([{"a": 1}, "x", -5])));
    assert!(
        !ok(&module("root = #6.1(int)"), json!(1)),
        "JSON carries no tag"
    );
}

#[test]
fn loading_refuses_what_it_cannot_check() {
    for (text, why) in [
        ("root = undefined-name", "not defined"),
        ("root = text .cbor uint", "not implemented"),
        (
            "root = pair<uint>\npair<A, B> = [A, B]",
            "takes 2 arguments",
        ),
        (
            "root = { * text => any, \"a\" => uint }",
            "literal key follows",
        ),
        ("root = { uint }", "without a key"),
        (
            "root = { * g }\ng = ( \"a\" => uint, \"b\" => uint )",
            "occurrence on a group",
        ),
        ("root = text .regexp \"[a-z-[aeiou]]\"", "subtraction"),
        ("root = 1.5", "floating-point"),
        ("root = &(a: 1)", "not implemented"),
        ("root = uint\nroot = text", "defined twice"),
        ("root /= uint", "not implemented"),
        ("root = text .regexp \"\\\\p{L}\"", "not implemented"),
    ] {
        let e = Module::parse(text).unwrap_err().to_string();
        assert!(e.contains(why), "{text:?}: {e}");
    }
}

#[test]
fn the_standard_carries_the_module() {
    let doc = include_str!("../../../docs/standard/cvm-attestation-v1.md");
    let appendix = doc
        .split("## Appendix C. CDDL module")
        .nth(1)
        .expect("the standard has appendix C");
    let block = appendix
        .split("```cddl\n")
        .nth(1)
        .and_then(|b| b.split("\n```").next())
        .expect("appendix C holds the module in a cddl block");
    assert_eq!(
        block,
        PROFILE.trim_end_matches('\n'),
        "appendix C and schemas/cvm-profile-v1.cddl differ"
    );
}
