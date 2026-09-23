//! The RFC 8610 grammar (appendix B), for the constructs the crate implements.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "line {}: {}", self.line, self.message)
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub params: Vec<String>,
    pub body: Body,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub enum Body {
    Type(Type),
    Group(Group),
}

/// A type choice.
#[derive(Debug, Clone)]
pub struct Type(pub Vec<Type1>);

#[derive(Debug, Clone)]
pub enum Type1 {
    Plain(Type2),
    Range {
        lo: Type2,
        hi: Type2,
        inclusive: bool,
    },
    Control {
        target: Type2,
        op: String,
        controller: Type2,
    },
}

#[derive(Debug, Clone)]
pub enum Type2 {
    Int(i128),
    Text(String),
    Name {
        name: String,
        args: Vec<Type1>,
    },
    Paren(Box<Type>),
    Map(Group),
    Array(Group),
    /// `~name`: the type inside the named tag or collection.
    Unwrap {
        name: String,
        args: Vec<Type1>,
    },
    /// `#6.n(type)`; JSON carries no tags, so the number is not kept.
    Tag {
        ty: Box<Type>,
    },
}

/// Group choices, each a sequence of entries.
#[derive(Debug, Clone)]
pub struct Group(pub Vec<Vec<Entry>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occur {
    pub min: u64,
    pub max: u64,
}

impl Occur {
    pub const ONE: Occur = Occur { min: 1, max: 1 };
}

#[derive(Debug, Clone)]
pub enum Entry {
    /// A member; without a key, the value is a type (in an array) or names a
    /// group (anywhere).
    Member {
        occur: Occur,
        key: Option<Key>,
        value: Type,
    },
    /// A parenthesized group.
    Group { occur: Occur, group: Group },
}

#[derive(Debug, Clone)]
pub struct Key {
    pub ty: Type1,
    pub cut: bool,
}

pub fn parse(text: &str) -> Result<BTreeMap<String, Rule>, Error> {
    let mut p = Parser {
        src: text.chars().collect(),
        pos: 0,
    };
    let mut rules = BTreeMap::new();
    loop {
        p.skip_ws();
        if p.eof() {
            break;
        }
        let rule = p.rule()?;
        if rules.contains_key(&rule.name) {
            return Err(p.err_at(rule.line, format!("rule {} is defined twice", rule.name)));
        }
        rules.insert(rule.name.clone(), rule);
    }
    Ok(rules)
}

struct Parser {
    src: Vec<char>,
    pos: usize,
}

fn ealpha(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '@' || c == '_' || c == '$'
}

impl Parser {
    fn eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    fn peek(&self) -> Option<char> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        self.src.get(self.pos + n).copied()
    }

    fn starts(&self, s: &str) -> bool {
        s.chars()
            .enumerate()
            .all(|(i, c)| self.peek_at(i) == Some(c))
    }

    fn eat(&mut self, s: &str) -> bool {
        if self.starts(s) {
            self.pos += s.chars().count();
            true
        } else {
            false
        }
    }

    fn line(&self) -> usize {
        1 + self.src[..self.pos.min(self.src.len())]
            .iter()
            .filter(|&&c| c == '\n')
            .count()
    }

    fn err(&self, message: impl Into<String>) -> Error {
        Error {
            line: self.line(),
            message: message.into(),
        }
    }

    fn err_at(&self, line: usize, message: impl Into<String>) -> Error {
        Error {
            line,
            message: message.into(),
        }
    }

    fn expect(&mut self, s: &str) -> Result<(), Error> {
        self.skip_ws();
        if self.eat(s) {
            Ok(())
        } else {
            Err(self.err(format!(
                "expected {s:?}, found {:?}",
                self.peek()
                    .map(String::from)
                    .unwrap_or_else(|| "end of input".into())
            )))
        }
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.pos += 1;
            } else if c == ';' {
                while let Some(c) = self.peek() {
                    self.pos += 1;
                    if c == '\n' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn ident(&mut self) -> Result<String, Error> {
        let start = self.pos;
        match self.peek() {
            Some(c) if ealpha(c) => self.pos += 1,
            _ => return Err(self.err("expected a name")),
        }
        loop {
            match self.peek() {
                Some(c) if ealpha(c) || c.is_ascii_digit() => self.pos += 1,
                Some('-') | Some('.') => {
                    let mut n = 0;
                    while matches!(self.peek_at(n), Some('-') | Some('.')) {
                        n += 1;
                    }
                    match self.peek_at(n) {
                        Some(c) if ealpha(c) || c.is_ascii_digit() => self.pos += n,
                        _ => break,
                    }
                }
                _ => break,
            }
        }
        Ok(self.src[start..self.pos].iter().collect())
    }

    fn rule(&mut self) -> Result<Rule, Error> {
        let line = self.line();
        let name = self.ident()?;
        let mut params = Vec::new();
        if self.peek() == Some('<') {
            self.pos += 1;
            loop {
                self.skip_ws();
                params.push(self.ident()?);
                self.skip_ws();
                if self.eat(",") {
                    continue;
                }
                self.expect(">")?;
                break;
            }
        }
        self.skip_ws();
        if self.starts("/=") || self.starts("//=") {
            return Err(self.err(format!("{name}: /= and //= are not implemented")));
        }
        self.expect("=")?;
        self.skip_ws();
        let body = if self.peek() == Some('(') {
            match self.paren()? {
                Paren::Group(g) => Body::Group(g),
                Paren::Type(t) => Body::Type(self.continue_type(t)?),
            }
        } else {
            Body::Type(self.ty()?)
        };
        Ok(Rule {
            name,
            params,
            body,
            line,
        })
    }

    /// `( ... )`: a group, or a type when it holds one keyless entry.
    fn paren(&mut self) -> Result<Paren, Error> {
        self.expect("(")?;
        let group = self.group(')')?;
        self.expect(")")?;
        if let [choice] = group.0.as_slice() {
            if let [Entry::Member {
                occur: Occur::ONE,
                key: None,
                value,
            }] = choice.as_slice()
            {
                return Ok(Paren::Type(Type2::Paren(Box::new(value.clone()))));
            }
        }
        Ok(Paren::Group(group))
    }

    /// After a parenthesized type, the rest of a type1 and the choice.
    fn continue_type(&mut self, first: Type2) -> Result<Type, Error> {
        let t1 = self.continue_type1(first)?;
        self.continue_choice(t1)
    }

    fn continue_choice(&mut self, first: Type1) -> Result<Type, Error> {
        let mut choices = vec![first];
        loop {
            let save = self.pos;
            self.skip_ws();
            if self.starts("/") && !self.starts("//") && !self.starts("/=") {
                self.pos += 1;
                choices.push(self.type1()?);
            } else {
                self.pos = save;
                return Ok(Type(choices));
            }
        }
    }

    fn ty(&mut self) -> Result<Type, Error> {
        let first = self.type1()?;
        self.continue_choice(first)
    }

    fn type1(&mut self) -> Result<Type1, Error> {
        let t2 = self.type2()?;
        self.continue_type1(t2)
    }

    fn continue_type1(&mut self, t2: Type2) -> Result<Type1, Error> {
        let save = self.pos;
        self.skip_ws();
        if self.eat("...") {
            let hi = self.type2()?;
            return Ok(Type1::Range {
                lo: t2,
                hi,
                inclusive: false,
            });
        }
        if self.eat("..") {
            let hi = self.type2()?;
            return Ok(Type1::Range {
                lo: t2,
                hi,
                inclusive: true,
            });
        }
        if self.peek() == Some('.') && self.peek_at(1).is_some_and(ealpha) {
            self.pos += 1;
            let op = self.ident()?;
            let controller = self.type2()?;
            return Ok(Type1::Control {
                target: t2,
                op,
                controller,
            });
        }
        self.pos = save;
        Ok(Type1::Plain(t2))
    }

    fn type2(&mut self) -> Result<Type2, Error> {
        self.skip_ws();
        match self.peek() {
            Some('"') => Ok(Type2::Text(self.text()?)),
            Some(c) if c.is_ascii_digit() || c == '-' => Ok(Type2::Int(self.int()?)),
            Some('(') => {
                self.pos += 1;
                let t = self.ty()?;
                self.expect(")")?;
                Ok(Type2::Paren(Box::new(t)))
            }
            Some('{') => {
                self.pos += 1;
                let g = self.group('}')?;
                self.expect("}")?;
                Ok(Type2::Map(g))
            }
            Some('[') => {
                self.pos += 1;
                let g = self.group(']')?;
                self.expect("]")?;
                Ok(Type2::Array(g))
            }
            Some('~') => {
                self.pos += 1;
                self.skip_ws();
                let name = self.ident()?;
                let args = self.args()?;
                Ok(Type2::Unwrap { name, args })
            }
            Some('#') => {
                self.pos += 1;
                if !self.eat("6") {
                    return Err(self.err("only #6 tags are implemented"));
                }
                if self.eat(".") {
                    self.uint()?;
                }
                self.expect("(")?;
                let ty = self.ty()?;
                self.expect(")")?;
                Ok(Type2::Tag { ty: Box::new(ty) })
            }
            Some('&') => Err(self.err("& (choices from a group) is not implemented")),
            Some(c) if ealpha(c) => {
                let name = self.ident()?;
                let args = self.args()?;
                Ok(Type2::Name { name, args })
            }
            _ => Err(self.err("expected a type")),
        }
    }

    fn args(&mut self) -> Result<Vec<Type1>, Error> {
        let mut args = Vec::new();
        if self.peek() != Some('<') {
            return Ok(args);
        }
        self.pos += 1;
        loop {
            self.skip_ws();
            args.push(self.type1()?);
            self.skip_ws();
            if self.eat(",") {
                continue;
            }
            self.expect(">")?;
            return Ok(args);
        }
    }

    fn group(&mut self, close: char) -> Result<Group, Error> {
        let mut choices = vec![Vec::new()];
        loop {
            self.skip_ws();
            match self.peek() {
                None => return Err(self.err(format!("expected {close:?}"))),
                Some(c) if c == close => return Ok(Group(choices)),
                _ => {}
            }
            if self.eat("//") {
                choices.push(Vec::new());
                continue;
            }
            let entry = self.entry()?;
            choices.last_mut().unwrap().push(entry);
            self.skip_ws();
            self.eat(",");
        }
    }

    fn entry(&mut self) -> Result<Entry, Error> {
        let occur = self.occur()?;
        self.skip_ws();
        let first = if self.peek() == Some('(') {
            match self.paren()? {
                Paren::Group(group) => return Ok(Entry::Group { occur, group }),
                // A parenthesized type: a member key or a keyless member.
                Paren::Type(t) => self.continue_type1(t)?,
            }
        } else {
            self.type1()?
        };
        self.skip_ws();
        if self.eat("^") {
            self.expect("=>")?;
            let value = self.ty()?;
            return Ok(Entry::Member {
                occur,
                key: Some(Key {
                    ty: first,
                    cut: true,
                }),
                value,
            });
        }
        if self.eat("=>") {
            let value = self.ty()?;
            return Ok(Entry::Member {
                occur,
                key: Some(Key {
                    ty: first,
                    cut: false,
                }),
                value,
            });
        }
        if self.peek() == Some(':') {
            self.pos += 1;
            // `bareword:` is a text key; `value:` is that value. Both cut.
            let key = match first {
                Type1::Plain(Type2::Name { name, args }) if args.is_empty() => {
                    Type1::Plain(Type2::Text(name))
                }
                t @ Type1::Plain(Type2::Text(_) | Type2::Int(_)) => t,
                _ => return Err(self.err("only a bareword or a value comes before ':'")),
            };
            let value = self.ty()?;
            return Ok(Entry::Member {
                occur,
                key: Some(Key { ty: key, cut: true }),
                value,
            });
        }
        Ok(Entry::Member {
            occur,
            key: None,
            value: self.continue_choice(first)?,
        })
    }

    fn occur(&mut self) -> Result<Occur, Error> {
        self.skip_ws();
        if self.eat("?") {
            return Ok(Occur { min: 0, max: 1 });
        }
        if self.eat("+") {
            return Ok(Occur {
                min: 1,
                max: u64::MAX,
            });
        }
        let save = self.pos;
        let min = if self.peek().is_some_and(|c| c.is_ascii_digit()) {
            Some(self.uint()?)
        } else {
            None
        };
        if self.eat("*") {
            let max = if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.uint()?
            } else {
                u64::MAX
            };
            let min = min.unwrap_or(0);
            if min > max {
                return Err(self.err(format!("occurrence {min}*{max}")));
            }
            return Ok(Occur { min, max });
        }
        self.pos = save;
        Ok(Occur::ONE)
    }

    fn uint(&mut self) -> Result<u64, Error> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
        let digits: String = self.src[start..self.pos].iter().collect();
        digits
            .parse()
            .map_err(|_| self.err(format!("{digits:?} is not an unsigned integer")))
    }

    fn int(&mut self) -> Result<i128, Error> {
        let negative = self.eat("-");
        if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
            return Err(self.err("expected digits"));
        }
        if self.starts("0x") || self.starts("0b") || self.starts("0o") {
            return Err(self.err("only decimal integers are implemented"));
        }
        let n = i128::from(self.uint()?);
        if self.peek() == Some('.') && self.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
            return Err(self.err("floating-point literals are not implemented"));
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            return Err(self.err("floating-point literals are not implemented"));
        }
        Ok(if negative { -n } else { n })
    }

    /// A text literal with the escapes of RFC 9682 section 2.1.
    fn text(&mut self) -> Result<String, Error> {
        self.expect("\"")?;
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.err("unterminated text"));
            };
            self.pos += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    let Some(e) = self.peek() else {
                        return Err(self.err("unterminated escape"));
                    };
                    self.pos += 1;
                    out.push(match e {
                        '"' => '"',
                        '\\' => '\\',
                        '/' => '/',
                        'b' => '\u{8}',
                        'f' => '\u{c}',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'u' => {
                            let hex: String = (0..4).filter_map(|i| self.peek_at(i)).collect();
                            let cp = u32::from_str_radix(&hex, 16)
                                .ok()
                                .filter(|_| hex.len() == 4)
                                .and_then(char::from_u32)
                                .ok_or_else(|| self.err(format!("\\u{hex} is not a character")))?;
                            self.pos += 4;
                            cp
                        }
                        _ => return Err(self.err(format!("\\{e} is not an escape"))),
                    });
                }
                c => out.push(c),
            }
        }
    }
}

enum Paren {
    Group(Group),
    Type(Type2),
}
