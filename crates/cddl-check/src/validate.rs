//! Static checks of a module, and matching JSON values against its rules.

use crate::parse::{Body, Entry, Error, Group, Occur, Rule, Type, Type1, Type2};
use crate::Module;
use base64::Engine;
use regex::Regex;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

const PRELUDE: &[&str] = &[
    "any", "bool", "true", "false", "null", "nil", "int", "uint", "nint", "text", "tstr", "bytes",
    "bstr", "float",
];

const CONTROLS: &[&str] = &[
    "size", "regexp", "lt", "le", "gt", "ge", "eq", "ne", "default", "feature", "within", "and",
    "b64u", "base10",
];

/// Generic parameters bound to the arguments of a reference, each with the
/// environment it is read in. Arguments are always part of the module, so
/// the environment borrows them.
#[derive(Clone, Default)]
struct Env<'m>(Option<Rc<HashMap<&'m str, (&'m Type1, Env<'m>)>>>);

impl<'m> Env<'m> {
    fn get(&self, name: &str) -> Option<&(&'m Type1, Env<'m>)> {
        self.0.as_ref()?.get(name)
    }

    fn bind(rule: &'m Rule, args: &'m [Type1], caller: &Env<'m>) -> Env<'m> {
        if rule.params.is_empty() {
            return Env::default();
        }
        Env(Some(Rc::new(
            rule.params
                .iter()
                .map(String::as_str)
                .zip(args.iter().map(|a| (a, caller.clone())))
                .collect(),
        )))
    }
}

impl Entry {
    fn occur(&self) -> Occur {
        match self {
            Entry::Member { occur, .. } | Entry::Group { occur, .. } => *occur,
        }
    }
}

fn err(rule: &Rule, message: impl Into<String>) -> Error {
    Error {
        line: rule.line,
        message: format!("{}: {}", rule.name, message.into()),
    }
}

// ---------------------------------------------------------------------------
// Static checks

pub fn check(module: &Module) -> Result<(), Error> {
    for rule in module.rules.values() {
        let c = Checker { module, rule };
        match &rule.body {
            Body::Type(t) => c.ty(t)?,
            Body::Group(g) => c.group(g, Where::Group)?,
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Where {
    Map,
    Array,
    /// A named or parenthesized group, checked where it is used.
    Group,
}

struct Checker<'m> {
    module: &'m Module,
    rule: &'m Rule,
}

impl<'m> Checker<'m> {
    fn is_param(&self, name: &str) -> bool {
        self.rule.params.iter().any(|p| p == name)
    }

    fn ty(&self, t: &'m Type) -> Result<(), Error> {
        t.0.iter().try_for_each(|t1| self.type1(t1))
    }

    fn type1(&self, t1: &'m Type1) -> Result<(), Error> {
        match t1 {
            Type1::Plain(t2) => self.type2(t2),
            Type1::Range { lo, hi, .. } => {
                self.type2(lo)?;
                self.type2(hi)
            }
            Type1::Control {
                target,
                op,
                controller,
            } => {
                if !CONTROLS.contains(&op.as_str()) {
                    return Err(err(self.rule, format!(".{op} is not implemented")));
                }
                self.type2(target)?;
                self.type2(controller)?;
                if op == "regexp" {
                    match controller {
                        Type2::Text(p) => {
                            compile(p).map_err(|e| err(self.rule, e))?;
                        }
                        _ => return Err(err(self.rule, ".regexp takes a text literal")),
                    }
                }
                if op == "feature" && !matches!(controller, Type2::Text(_)) {
                    return Err(err(self.rule, ".feature takes a text literal"));
                }
                Ok(())
            }
        }
    }

    fn type2(&self, t2: &'m Type2) -> Result<(), Error> {
        match t2 {
            Type2::Int(_) | Type2::Text(_) => Ok(()),
            Type2::Name { name, args } => {
                args.iter().try_for_each(|a| self.type1(a))?;
                self.name(name, args.len(), false)
            }
            Type2::Paren(t) => self.ty(t),
            Type2::Map(g) => self.group(g, Where::Map),
            Type2::Array(g) => self.group(g, Where::Array),
            Type2::Unwrap { name, args } => {
                args.iter().try_for_each(|a| self.type1(a))?;
                self.name(name, args.len(), false)?;
                match self.module.rules.get(name).map(|r| &r.body) {
                    Some(Body::Type(Type(c)))
                        if matches!(c.as_slice(), [Type1::Plain(Type2::Tag { .. })]) =>
                    {
                        Ok(())
                    }
                    _ => Err(err(self.rule, format!("~{name}: only a tag is unwrapped"))),
                }
            }
            Type2::Tag { ty, .. } => self.ty(ty),
        }
    }

    /// A name resolves to a parameter, a rule of the right arity or the
    /// prelude; `group` says whether a group is what the position takes.
    fn name(&self, name: &str, arity: usize, group: bool) -> Result<(), Error> {
        if self.is_param(name) {
            return if arity == 0 {
                Ok(())
            } else {
                Err(err(
                    self.rule,
                    format!("parameter {name} takes no arguments"),
                ))
            };
        }
        if let Some(r) = self.module.rules.get(name) {
            if r.params.len() != arity {
                return Err(err(
                    self.rule,
                    format!("{name} takes {} arguments, not {arity}", r.params.len()),
                ));
            }
            return match (&r.body, group) {
                (Body::Group(_), false) => Err(err(
                    self.rule,
                    format!("{name} is a group where a type goes"),
                )),
                _ => Ok(()),
            };
        }
        if PRELUDE.contains(&name) && arity == 0 {
            return Ok(());
        }
        Err(err(self.rule, format!("{name} is not defined")))
    }

    fn group_rule(&self, value: &Type) -> Option<&'m Rule> {
        match value.0.as_slice() {
            [Type1::Plain(Type2::Name { name, .. })] if !self.is_param(name) => self
                .module
                .rules
                .get(name)
                .filter(|r| matches!(r.body, Body::Group(_))),
            _ => None,
        }
    }

    fn group(&self, g: &'m Group, at: Where) -> Result<(), Error> {
        for choice in &g.0 {
            for entry in choice {
                self.entry(entry, at)?;
            }
            if at == Where::Map {
                self.member_order(choice)?;
            }
        }
        Ok(())
    }

    fn entry(&self, entry: &'m Entry, at: Where) -> Result<(), Error> {
        match entry {
            // In an array a key is a label; its value is what matches.
            Entry::Member {
                key: Some(key),
                value,
                ..
            } => {
                self.type1(&key.ty)?;
                self.ty(value)
            }
            Entry::Member {
                occur,
                key: None,
                value,
            } => {
                if let [Type1::Plain(Type2::Name { name, args })] = value.0.as_slice() {
                    args.iter().try_for_each(|a| self.type1(a))?;
                    if let Some(r) = self.group_rule(value) {
                        self.name(name, args.len(), true)?;
                        let Body::Group(g) = &r.body else {
                            unreachable!()
                        };
                        return self.group_occurrence(*occur, g, at);
                    }
                }
                if at == Where::Map {
                    return Err(err(self.rule, "a map entry without a key names no group"));
                }
                self.ty(value)
            }
            Entry::Group { occur, group } => {
                self.group(group, if at == Where::Group { Where::Group } else { at })?;
                self.group_occurrence(*occur, group, at)
            }
        }
    }

    /// An occurrence on a group entry: one, or a map group of one member,
    /// which the occurrence then applies to.
    fn group_occurrence(&self, occur: Occur, g: &Group, at: Where) -> Result<(), Error> {
        if occur == Occur::ONE {
            return Ok(());
        }
        let single = matches!(g.0.as_slice(), [c] if matches!(c.as_slice(),
            [e @ Entry::Member { key: Some(_), .. }] if e.occur() == Occur::ONE));
        if at != Where::Array && single {
            return Ok(());
        }
        Err(err(
            self.rule,
            "an occurrence on a group is implemented only for a map group of one member",
        ))
    }

    /// Members are matched in order, each taking the object members its key
    /// matches, so a key that is not a literal must come after every literal
    /// key of the same map, or it could take a member a later entry needs.
    fn member_order(&self, entries: &'m [Entry]) -> Result<(), Error> {
        let mut keys = Vec::new();
        self.flatten_keys(entries, &Env::default(), &mut keys, 0)?;
        let mut open = false;
        for literal in keys {
            if !literal {
                open = true;
            } else if open {
                return Err(err(
                    self.rule,
                    "a literal key follows a key that is not a literal in the same map",
                ));
            }
        }
        Ok(())
    }

    fn flatten_keys(
        &self,
        entries: &'m [Entry],
        env: &Env<'m>,
        out: &mut Vec<bool>,
        depth: usize,
    ) -> Result<(), Error> {
        if depth > 32 {
            return Err(err(self.rule, "groups nest deeper than 32"));
        }
        for entry in entries {
            match entry {
                Entry::Member { key: Some(key), .. } => out.push(self.literal_key(&key.ty, env, 0)),
                Entry::Member {
                    key: None, value, ..
                } => {
                    if let (Some(r), [Type1::Plain(Type2::Name { args, .. })]) =
                        (self.group_rule(value), value.0.as_slice())
                    {
                        let Body::Group(g) = &r.body else {
                            unreachable!()
                        };
                        let inner = Env::bind(r, args, env);
                        for choice in &g.0 {
                            self.flatten_keys(choice, &inner, out, depth + 1)?;
                        }
                    }
                }
                Entry::Group { group, .. } => {
                    for choice in &group.0 {
                        self.flatten_keys(choice, env, out, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether a key type matches only literal values.
    fn literal_key(&self, t1: &'m Type1, env: &Env<'m>, depth: usize) -> bool {
        if depth > 32 {
            return false;
        }
        match t1 {
            Type1::Plain(t2) => self.literal_type2(t2, env, depth),
            Type1::Control { target, op, .. } if op == "feature" || op == "default" => {
                self.literal_type2(target, env, depth)
            }
            _ => false,
        }
    }

    fn literal_type2(&self, t2: &'m Type2, env: &Env<'m>, depth: usize) -> bool {
        match t2 {
            Type2::Int(_) | Type2::Text(_) => true,
            Type2::Paren(t) => t.0.iter().all(|t1| self.literal_key(t1, env, depth + 1)),
            Type2::Name { name, args } => {
                if let Some((bound, benv)) = env.get(name) {
                    return self.literal_key(bound, benv, depth + 1);
                }
                match self.module.rules.get(name) {
                    Some(r) => match &r.body {
                        Body::Type(t) => {
                            let inner = Env::bind(r, args, env);
                            t.0.iter().all(|t1| self.literal_key(t1, &inner, depth + 1))
                        }
                        Body::Group(_) => false,
                    },
                    None => false,
                }
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Matching

/// XSD regular expressions (RFC 8610 section 3.8.3) as the regex crate's,
/// anchored at both ends as XSD patterns are.
fn compile(pattern: &str) -> Result<Regex, String> {
    let mut out = String::from("^(?:");
    let mut class = false;
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let e = chars.next().ok_or("a trailing backslash")?;
                if matches!(e, 'i' | 'I' | 'c' | 'C' | 'p' | 'P') {
                    return Err(format!("\\{e} is not implemented"));
                }
                out.push('\\');
                out.push(e);
            }
            '[' if class => return Err("character class subtraction is not implemented".into()),
            '[' => {
                class = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    chars.next();
                    out.push('^');
                }
            }
            ']' if class => {
                class = false;
                out.push(']');
            }
            // Set operations in the regex crate, plain characters in XSD.
            '&' | '~' | '-' if class && chars.peek() == Some(&c) => {
                return Err(format!("{c}{c} inside a class is not implemented"));
            }
            // Anchors in the regex crate, plain characters in XSD.
            '^' | '$' if !class => {
                out.push('\\');
                out.push(c);
            }
            // XSD's `.` excludes both line ends.
            '.' if !class => out.push_str(r"[^\n\r]"),
            c => out.push(c),
        }
    }
    if class {
        return Err("an unterminated character class".into());
    }
    out.push_str(")$");
    Regex::new(&out).map_err(|e| format!("regexp {pattern:?}: {e}"))
}

#[derive(Clone, Copy)]
enum Val<'a> {
    Json(&'a Value),
    /// What `.b64u` decodes.
    Bytes(&'a [u8]),
    /// What `.base10` reads, and a length `.size` measures.
    Int(i128),
}

fn int_of(v: Val) -> Option<i128> {
    match v {
        Val::Int(n) => Some(n),
        Val::Json(Value::Number(n)) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from)),
        _ => None,
    }
}

struct Matcher<'m> {
    module: &'m Module,
    features: &'m [&'m str],
    regexes: RefCell<HashMap<String, Rc<Regex>>>,
}

/// An entry still to match, with the occurrence that applies and the
/// environment it is read in.
#[derive(Clone)]
struct Pending<'m> {
    entry: &'m Entry,
    occur: Occur,
    env: Env<'m>,
}

pub fn validate(
    module: &Module,
    root: &str,
    value: &Value,
    features: &[&str],
) -> Result<bool, Error> {
    let rule = module.rules.get(root).ok_or_else(|| Error {
        line: 0,
        message: format!("{root} is not defined"),
    })?;
    if !rule.params.is_empty() {
        return Err(err(rule, "a root takes no arguments"));
    }
    let Body::Type(t) = &rule.body else {
        return Err(err(rule, "a root is a type"));
    };
    let m = Matcher {
        module,
        features,
        regexes: RefCell::new(HashMap::new()),
    };
    Ok(m.ty(t, Val::Json(value), &Env::default()))
}

impl<'m> Matcher<'m> {
    fn ty(&self, t: &'m Type, v: Val, env: &Env<'m>) -> bool {
        t.0.iter().any(|t1| self.type1(t1, v, env))
    }

    fn type1(&self, t1: &'m Type1, v: Val, env: &Env<'m>) -> bool {
        match t1 {
            Type1::Plain(t2) => self.type2(t2, v, env),
            Type1::Range { lo, hi, inclusive } => {
                match (
                    int_of(v),
                    self.int_literal(lo, env),
                    self.int_literal(hi, env),
                ) {
                    (Some(n), Some(lo), Some(hi)) => {
                        n >= lo && if *inclusive { n <= hi } else { n < hi }
                    }
                    _ => false,
                }
            }
            Type1::Control {
                target,
                op,
                controller,
            } => self.control(target, op, controller, v, env),
        }
    }

    fn control(
        &self,
        target: &'m Type2,
        op: &str,
        controller: &'m Type2,
        v: Val,
        env: &Env<'m>,
    ) -> bool {
        match op {
            "size" => {
                if !self.type2(target, v, env) {
                    return false;
                }
                let len = match v {
                    Val::Json(Value::String(s)) => s.len(),
                    Val::Bytes(b) => b.len(),
                    _ => return false,
                };
                self.type2(controller, Val::Int(len as i128), env)
            }
            "regexp" => {
                let Val::Json(Value::String(s)) = v else {
                    return false;
                };
                self.type2(target, v, env)
                    && match self.text_literal(controller, env) {
                        Some(p) => self.regex(p).is_match(s),
                        None => false,
                    }
            }
            "b64u" => {
                let Val::Json(Value::String(s)) = v else {
                    return false;
                };
                if !self.type2(target, v, env) {
                    return false;
                }
                // RFC 9741: the URL-safe alphabet, no padding, zero trailing bits.
                match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s) {
                    Ok(b) => self.type2(controller, Val::Bytes(&b), env),
                    Err(_) => false,
                }
            }
            "base10" => {
                let Val::Json(Value::String(s)) = v else {
                    return false;
                };
                // RFC 9741 section 2.2: 0 or -?[1-9][0-9]*, no leading zeros.
                let digits = s.strip_prefix('-').unwrap_or(s);
                let canonical = s == "0"
                    || (digits.starts_with(|c: char| ('1'..='9').contains(&c))
                        && digits.chars().all(|c| c.is_ascii_digit()));
                canonical
                    && self.type2(target, v, env)
                    && s.parse::<i128>()
                        .is_ok_and(|n| self.type2(controller, Val::Int(n), env))
            }
            "feature" => {
                self.text_literal(controller, env)
                    .is_some_and(|f| self.features.contains(&f))
                    && self.type2(target, v, env)
            }
            "within" | "and" => self.type2(target, v, env) && self.type2(controller, v, env),
            "lt" | "le" | "gt" | "ge" | "eq" | "ne" => {
                self.type2(target, v, env)
                    && match (int_of(v), self.int_literal(controller, env)) {
                        (Some(a), Some(b)) => match op {
                            "lt" => a < b,
                            "le" => a <= b,
                            "gt" => a > b,
                            "ge" => a >= b,
                            "eq" => a == b,
                            _ => a != b,
                        },
                        _ => false,
                    }
            }
            "default" => self.type2(target, v, env),
            _ => false,
        }
    }

    fn regex(&self, pattern: &str) -> Rc<Regex> {
        if let Some(r) = self.regexes.borrow().get(pattern) {
            return r.clone();
        }
        let r = Rc::new(compile(pattern).expect("checked when the module loaded"));
        self.regexes
            .borrow_mut()
            .insert(pattern.to_string(), r.clone());
        r
    }

    /// The single type a literal-like type2 stands for: through parameters,
    /// parentheses and rules of one plain alternative.
    fn literal(&self, t2: &'m Type2, env: &Env<'m>, depth: usize) -> Option<&'m Type2> {
        if depth > 32 {
            return None;
        }
        match t2 {
            Type2::Int(_) | Type2::Text(_) => Some(t2),
            Type2::Name { name, args } => {
                if let Some((Type1::Plain(bound), benv)) = env.get(name) {
                    return self.literal(bound, benv, depth + 1);
                }
                let r = self.module.rules.get(name)?;
                match &r.body {
                    Body::Type(Type(c)) => match c.as_slice() {
                        [Type1::Plain(inner)] => {
                            self.literal(inner, &Env::bind(r, args, env), depth + 1)
                        }
                        _ => None,
                    },
                    Body::Group(_) => None,
                }
            }
            Type2::Paren(t) => match t.0.as_slice() {
                [Type1::Plain(inner)] => self.literal(inner, env, depth + 1),
                _ => None,
            },
            _ => None,
        }
    }

    fn text_literal(&self, t2: &'m Type2, env: &Env<'m>) -> Option<&'m str> {
        match self.literal(t2, env, 0)? {
            Type2::Text(s) => Some(s),
            _ => None,
        }
    }

    fn int_literal(&self, t2: &'m Type2, env: &Env<'m>) -> Option<i128> {
        match self.literal(t2, env, 0)? {
            Type2::Int(n) => Some(*n),
            _ => None,
        }
    }

    fn type2(&self, t2: &'m Type2, v: Val, env: &Env<'m>) -> bool {
        match t2 {
            Type2::Int(n) => int_of(v) == Some(*n),
            Type2::Text(s) => matches!(v, Val::Json(Value::String(x)) if x == s),
            Type2::Name { name, args } => self.name(name, args, v, env),
            Type2::Paren(t) => self.ty(t, v, env),
            Type2::Map(g) => match v {
                Val::Json(Value::Object(o)) => self.map(g, o, env),
                _ => false,
            },
            Type2::Array(g) => match v {
                Val::Json(Value::Array(a)) => self.array(g, a, env),
                _ => false,
            },
            Type2::Unwrap { name, args } => {
                let Some(r) = self.module.rules.get(name) else {
                    return false;
                };
                match &r.body {
                    Body::Type(Type(c)) => match c.as_slice() {
                        [Type1::Plain(Type2::Tag { ty, .. })] => {
                            self.ty(ty, v, &Env::bind(r, args, env))
                        }
                        _ => false,
                    },
                    Body::Group(_) => false,
                }
            }
            // JSON carries no tags; `~` reaches the type inside one.
            Type2::Tag { .. } => false,
        }
    }

    fn name(&self, name: &str, args: &'m [Type1], v: Val, env: &Env<'m>) -> bool {
        if let Some((bound, benv)) = env.get(name) {
            return self.type1(bound, v, benv);
        }
        if let Some(r) = self.module.rules.get(name) {
            return match &r.body {
                Body::Type(t) => self.ty(t, v, &Env::bind(r, args, env)),
                Body::Group(_) => false,
            };
        }
        match name {
            "any" => true,
            "bool" => matches!(v, Val::Json(Value::Bool(_))),
            "true" => matches!(v, Val::Json(Value::Bool(true))),
            "false" => matches!(v, Val::Json(Value::Bool(false))),
            "null" | "nil" => matches!(v, Val::Json(Value::Null)),
            "int" => int_of(v).is_some(),
            "uint" => int_of(v).is_some_and(|n| n >= 0),
            "nint" => int_of(v).is_some_and(|n| n < 0),
            "text" | "tstr" => matches!(v, Val::Json(Value::String(_))),
            "bytes" | "bstr" => matches!(v, Val::Bytes(_)),
            "float" => matches!(v, Val::Json(Value::Number(n)) if n.is_f64()),
            _ => false,
        }
    }

    fn group_rule(&self, value: &'m Type, env: &Env<'m>) -> Option<(&'m Group, Env<'m>)> {
        match value.0.as_slice() {
            [Type1::Plain(Type2::Name { name, args })] if env.get(name).is_none() => {
                let r = self.module.rules.get(name)?;
                match &r.body {
                    Body::Group(g) => Some((g, Env::bind(r, args, env))),
                    Body::Type(_) => None,
                }
            }
            _ => None,
        }
    }

    fn pending(choice: &'m [Entry], env: &Env<'m>) -> Vec<Pending<'m>> {
        choice
            .iter()
            .map(|entry| Pending {
                entry,
                occur: entry.occur(),
                env: env.clone(),
            })
            .collect()
    }

    fn map(&self, g: &'m Group, o: &serde_json::Map<String, Value>, env: &Env<'m>) -> bool {
        let members: Vec<(Value, &Value)> = o
            .iter()
            .map(|(k, v)| (Value::String(k.clone()), v))
            .collect();
        g.0.iter().any(|choice| {
            self.map_seq(
                &Self::pending(choice, env),
                &members,
                vec![false; members.len()],
            )
        })
    }

    /// Entries in order; each member entry takes the object members its key
    /// matches, and a cut makes a matching key with a wrong value fatal.
    fn map_seq(
        &self,
        pending: &[Pending<'m>],
        members: &[(Value, &Value)],
        consumed: Vec<bool>,
    ) -> bool {
        let Some((first, rest)) = pending.split_first() else {
            return consumed.iter().all(|&c| c);
        };
        match first.entry {
            Entry::Member {
                key: Some(key),
                value,
                ..
            } => {
                let mut consumed = consumed;
                let mut count = 0u64;
                for (i, (k, v)) in members.iter().enumerate() {
                    if consumed[i] || count == first.occur.max {
                        continue;
                    }
                    if !self.type1(&key.ty, Val::Json(k), &first.env) {
                        continue;
                    }
                    if self.ty(value, Val::Json(v), &first.env) {
                        consumed[i] = true;
                        count += 1;
                    } else if key.cut {
                        return false;
                    }
                }
                count >= first.occur.min && self.map_seq(rest, members, consumed)
            }
            Entry::Member {
                key: None, value, ..
            } => match self.group_rule(value, &first.env) {
                Some((g, genv)) => self.map_group(first.occur, g, &genv, rest, members, consumed),
                None => false,
            },
            Entry::Group { group, .. } => {
                self.map_group(first.occur, group, &first.env, rest, members, consumed)
            }
        }
    }

    fn map_group(
        &self,
        occur: Occur,
        g: &'m Group,
        genv: &Env<'m>,
        rest: &[Pending<'m>],
        members: &[(Value, &Value)],
        consumed: Vec<bool>,
    ) -> bool {
        if occur == Occur::ONE {
            return g.0.iter().any(|choice| {
                let mut next = Self::pending(choice, genv);
                next.extend(rest.iter().cloned());
                self.map_seq(&next, members, consumed.clone())
            });
        }
        // Checked at load: a group of one member, which takes the occurrence.
        let [choice] = g.0.as_slice() else {
            return false;
        };
        let [entry] = choice.as_slice() else {
            return false;
        };
        let mut next = vec![Pending {
            entry,
            occur,
            env: genv.clone(),
        }];
        next.extend(rest.iter().cloned());
        self.map_seq(&next, members, consumed)
    }

    fn array(&self, g: &'m Group, items: &[Value], env: &Env<'m>) -> bool {
        g.0.iter()
            .any(|choice| self.array_seq(&Self::pending(choice, env), items))
    }

    /// Entries in order against the items, trying the longest run an
    /// occurrence allows first and backtracking to shorter ones.
    fn array_seq(&self, pending: &[Pending<'m>], items: &[Value]) -> bool {
        let Some((first, rest)) = pending.split_first() else {
            return items.is_empty();
        };
        let value = match first.entry {
            Entry::Member { value, .. } => {
                if let Some((g, genv)) = self.group_rule(value, &first.env) {
                    return self.array_group(g, &genv, rest, items);
                }
                value
            }
            Entry::Group { group, .. } => return self.array_group(group, &first.env, rest, items),
        };
        let mut n = 0usize;
        while n < items.len()
            && (n as u64) < first.occur.max
            && self.ty(value, Val::Json(&items[n]), &first.env)
        {
            n += 1;
        }
        if (n as u64) < first.occur.min {
            return false;
        }
        (first.occur.min as usize..=n)
            .rev()
            .any(|k| self.array_seq(rest, &items[k..]))
    }

    fn array_group(
        &self,
        g: &'m Group,
        genv: &Env<'m>,
        rest: &[Pending<'m>],
        items: &[Value],
    ) -> bool {
        g.0.iter().any(|choice| {
            let mut next = Self::pending(choice, genv);
            next.extend(rest.iter().cloned());
            self.array_seq(&next, items)
        })
    }
}
