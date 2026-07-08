//! Integer arithmetic evaluation for `$(( … ))` (Phase 3, POSIX §2.6.4).
//!
//! Signed [`i64`] ("at least `long`") with the full C-like operator set:
//! `+ - * / % **`, comparison, logical `&& || !`, bitwise `& | ^ ~ << >>`, the
//! ternary `?:`, and assignment operators — over parenthesised sub-expressions
//! and variable references. Short-circuit operators (`&&`, `||`, `?:`) do not
//! evaluate — and their assignments do not fire — on the dead branch.
//!
//! Variable references evaluate the variable's *string value* as an arithmetic
//! expression (recursively, e.g. `a=b+1` then `$((a))`), guarded by a recursion
//! limit. The evaluator is decoupled from the shell via [`ArithEnv`] so it can
//! be unit-tested in isolation.

/// The variable store the evaluator reads and writes.
pub trait ArithEnv {
    /// The variable's raw string value, or `None` if unset.
    fn get(&self, name: &str) -> Option<String>;
    /// Assign an integer result back to a variable (as its decimal string).
    fn set(&mut self, name: &str, value: i64);
}

const MAX_DEPTH: usize = 64;

/// Evaluate an arithmetic expression, returning its value or an error message.
pub fn eval(expr: &str, env: &mut dyn ArithEnv) -> Result<i64, String> {
    let toks = tokenize(expr)?;
    let mut ev = Eval {
        toks,
        pos: 0,
        env,
        depth: 0,
    };
    let v = ev.assignment(true)?;
    if ev.pos != ev.toks.len() {
        return Err("unexpected trailing tokens in arithmetic expression".to_string());
    }
    Ok(v)
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(i64),
    Ident(String),
    Op(Op),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Assign,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    ModAssign,
    ShlAssign,
    ShrAssign,
    AndAssign,
    OrAssign,
    XorAssign,
    Question,
    Colon,
    OrOr,
    AndAnd,
    BitOr,
    BitXor,
    BitAnd,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Shl,
    Shr,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Not,
    BitNot,
    LParen,
    RParen,
}

/// Operators tried longest-first so `<<=` beats `<<` beats `<`.
const OPERATORS: &[(&str, Op)] = &[
    ("<<=", Op::ShlAssign),
    (">>=", Op::ShrAssign),
    ("**", Op::Pow),
    ("<<", Op::Shl),
    (">>", Op::Shr),
    ("<=", Op::Le),
    (">=", Op::Ge),
    ("==", Op::Eq),
    ("!=", Op::Ne),
    ("&&", Op::AndAnd),
    ("||", Op::OrOr),
    ("*=", Op::MulAssign),
    ("/=", Op::DivAssign),
    ("%=", Op::ModAssign),
    ("+=", Op::AddAssign),
    ("-=", Op::SubAssign),
    ("&=", Op::AndAssign),
    ("|=", Op::OrAssign),
    ("^=", Op::XorAssign),
    ("=", Op::Assign),
    ("+", Op::Add),
    ("-", Op::Sub),
    ("*", Op::Mul),
    ("/", Op::Div),
    ("%", Op::Mod),
    ("<", Op::Lt),
    (">", Op::Gt),
    ("&", Op::BitAnd),
    ("|", Op::BitOr),
    ("^", Op::BitXor),
    ("~", Op::BitNot),
    ("!", Op::Not),
    ("?", Op::Question),
    (":", Op::Colon),
    ("(", Op::LParen),
    (")", Op::RParen),
];

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut toks = Vec::new();
    'outer: while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let (val, next) = parse_number(&chars, i)?;
            toks.push(Tok::Num(val));
            i = next;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            toks.push(Tok::Ident(chars[start..i].iter().collect()));
            continue;
        }
        for (text, op) in OPERATORS {
            let n = text.chars().count();
            if chars[i..].len() >= n && chars[i..i + n].iter().collect::<String>() == *text {
                toks.push(Tok::Op(*op));
                i += n;
                continue 'outer;
            }
        }
        return Err(format!("unexpected character `{c}` in arithmetic expression"));
    }
    Ok(toks)
}

/// Parse a C-style integer literal: `0x…` hex, `0…` octal, else decimal.
fn parse_number(chars: &[char], start: usize) -> Result<(i64, usize), String> {
    let mut i = start;
    let (radix, digit_start) = if chars[i] == '0' && i + 1 < chars.len() && matches!(chars[i + 1], 'x' | 'X') {
        (16, i + 2)
    } else if chars[i] == '0' {
        (8, i)
    } else {
        (10, i)
    };
    i = digit_start;
    let ds = i;
    while i < chars.len() && chars[i].is_digit(radix) {
        i += 1;
    }
    let text: String = chars[ds..i].iter().collect();
    let text = if text.is_empty() && radix == 8 {
        "0".to_string() // a lone "0"
    } else {
        text
    };
    match i64::from_str_radix(&text, radix) {
        Ok(v) => Ok((v, i)),
        Err(_) => Err(format!("invalid number `{}`", chars[start..i].iter().collect::<String>())),
    }
}

struct Eval<'e> {
    toks: Vec<Tok>,
    pos: usize,
    env: &'e mut dyn ArithEnv,
    depth: usize,
}

impl Eval<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn peek_op(&self) -> Option<Op> {
        match self.toks.get(self.pos) {
            Some(Tok::Op(o)) => Some(*o),
            _ => None,
        }
    }
    fn bump(&mut self) {
        self.pos += 1;
    }
    fn expect(&mut self, op: Op, what: &str) -> Result<(), String> {
        if self.peek_op() == Some(op) {
            self.bump();
            Ok(())
        } else {
            Err(format!("expected `{what}` in arithmetic expression"))
        }
    }

    /// Read the current variable's value as an integer (its string re-evaluated
    /// as arithmetic; unset/empty → 0).
    fn var_value(&mut self, name: &str) -> Result<i64, String> {
        if self.depth >= MAX_DEPTH {
            return Err("arithmetic recursion limit exceeded".to_string());
        }
        match self.env.get(name) {
            None => Ok(0),
            Some(s) if s.trim().is_empty() => Ok(0),
            Some(s) => {
                let toks = tokenize(&s)?;
                let mut inner = Eval {
                    toks,
                    pos: 0,
                    env: self.env,
                    depth: self.depth + 1,
                };
                let v = inner.assignment(true)?;
                if inner.pos != inner.toks.len() {
                    return Err(format!("invalid arithmetic value `{s}` for `{name}`"));
                }
                Ok(v)
            }
        }
    }

    fn assignment(&mut self, active: bool) -> Result<i64, String> {
        // An assignment is `name <assign-op> value`; detect it by lookahead.
        if let Some(Tok::Ident(name)) = self.peek().cloned()
            && let Some(Tok::Op(op)) = self.toks.get(self.pos + 1).cloned()
            && is_assign_op(op)
        {
            self.bump(); // name
            self.bump(); // op
            let rhs = self.assignment(active)?; // right-associative
            if !active {
                return Ok(0);
            }
            let value = if op == Op::Assign {
                rhs
            } else {
                let cur = self.var_value(&name)?;
                apply_binary(compound_base(op), cur, rhs)?
            };
            self.env.set(&name, value);
            return Ok(value);
        }
        self.ternary(active)
    }

    fn ternary(&mut self, active: bool) -> Result<i64, String> {
        let cond = self.logical_or(active)?;
        if self.peek_op() == Some(Op::Question) {
            self.bump();
            let take = cond != 0;
            let then = self.assignment(active && take)?;
            self.expect(Op::Colon, ":")?;
            let els = self.ternary(active && !take)?;
            Ok(if take { then } else { els })
        } else {
            Ok(cond)
        }
    }

    fn logical_or(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.logical_and(active)?;
        while self.peek_op() == Some(Op::OrOr) {
            self.bump();
            let r = self.logical_and(active && l == 0)?;
            if active {
                l = ((l != 0) || (r != 0)) as i64;
            }
        }
        Ok(l)
    }

    fn logical_and(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.bit_or(active)?;
        while self.peek_op() == Some(Op::AndAnd) {
            self.bump();
            let r = self.bit_or(active && l != 0)?;
            if active {
                l = ((l != 0) && (r != 0)) as i64;
            }
        }
        Ok(l)
    }

    fn bit_or(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.bit_xor(active)?;
        while self.peek_op() == Some(Op::BitOr) {
            self.bump();
            let r = self.bit_xor(active)?;
            l |= r;
        }
        Ok(l)
    }

    fn bit_xor(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.bit_and(active)?;
        while self.peek_op() == Some(Op::BitXor) {
            self.bump();
            let r = self.bit_and(active)?;
            l ^= r;
        }
        Ok(l)
    }

    fn bit_and(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.equality(active)?;
        while self.peek_op() == Some(Op::BitAnd) {
            self.bump();
            let r = self.equality(active)?;
            l &= r;
        }
        Ok(l)
    }

    fn equality(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.relational(active)?;
        while let Some(op @ (Op::Eq | Op::Ne)) = self.peek_op() {
            self.bump();
            let r = self.relational(active)?;
            l = match op {
                Op::Eq => (l == r) as i64,
                _ => (l != r) as i64,
            };
        }
        Ok(l)
    }

    fn relational(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.shift(active)?;
        while let Some(op @ (Op::Lt | Op::Le | Op::Gt | Op::Ge)) = self.peek_op() {
            self.bump();
            let r = self.shift(active)?;
            l = match op {
                Op::Lt => (l < r) as i64,
                Op::Le => (l <= r) as i64,
                Op::Gt => (l > r) as i64,
                _ => (l >= r) as i64,
            };
        }
        Ok(l)
    }

    fn shift(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.additive(active)?;
        while let Some(op @ (Op::Shl | Op::Shr)) = self.peek_op() {
            self.bump();
            let r = self.additive(active)?;
            l = apply_binary(op, l, r)?;
        }
        Ok(l)
    }

    fn additive(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.multiplicative(active)?;
        while let Some(op @ (Op::Add | Op::Sub)) = self.peek_op() {
            self.bump();
            let r = self.multiplicative(active)?;
            l = apply_binary(op, l, r)?;
        }
        Ok(l)
    }

    fn multiplicative(&mut self, active: bool) -> Result<i64, String> {
        let mut l = self.unary(active)?;
        while let Some(op @ (Op::Mul | Op::Div | Op::Mod)) = self.peek_op() {
            self.bump();
            let r = self.unary(active)?;
            if active {
                l = apply_binary(op, l, r)?;
            }
        }
        Ok(l)
    }

    fn unary(&mut self, active: bool) -> Result<i64, String> {
        match self.peek_op() {
            Some(Op::Sub) => {
                self.bump();
                Ok(self.unary(active)?.wrapping_neg())
            }
            Some(Op::Add) => {
                self.bump();
                self.unary(active)
            }
            Some(Op::Not) => {
                self.bump();
                Ok((self.unary(active)? == 0) as i64)
            }
            Some(Op::BitNot) => {
                self.bump();
                Ok(!self.unary(active)?)
            }
            _ => self.power(active),
        }
    }

    fn power(&mut self, active: bool) -> Result<i64, String> {
        let base = self.primary(active)?;
        if self.peek_op() == Some(Op::Pow) {
            self.bump();
            let exp = self.unary(active)?; // right-associative
            if active {
                if exp < 0 {
                    return Err("exponent less than 0 in arithmetic expression".to_string());
                }
                return Ok(base.wrapping_pow(exp as u32));
            }
        }
        Ok(base)
    }

    fn primary(&mut self, active: bool) -> Result<i64, String> {
        match self.peek().cloned() {
            Some(Tok::Num(n)) => {
                self.bump();
                Ok(n)
            }
            Some(Tok::Ident(name)) => {
                self.bump();
                self.var_value(&name)
            }
            Some(Tok::Op(Op::LParen)) => {
                self.bump();
                let v = self.assignment(active)?;
                self.expect(Op::RParen, ")")?;
                Ok(v)
            }
            other => Err(format!(
                "unexpected token in arithmetic expression near {}",
                match other {
                    None => "end of expression".to_string(),
                    Some(_) => "operator".to_string(),
                }
            )),
        }
    }
}

fn is_assign_op(op: Op) -> bool {
    matches!(
        op,
        Op::Assign
            | Op::AddAssign
            | Op::SubAssign
            | Op::MulAssign
            | Op::DivAssign
            | Op::ModAssign
            | Op::ShlAssign
            | Op::ShrAssign
            | Op::AndAssign
            | Op::OrAssign
            | Op::XorAssign
    )
}

/// The binary operator underlying a compound assignment (`+=` → `+`).
fn compound_base(op: Op) -> Op {
    match op {
        Op::AddAssign => Op::Add,
        Op::SubAssign => Op::Sub,
        Op::MulAssign => Op::Mul,
        Op::DivAssign => Op::Div,
        Op::ModAssign => Op::Mod,
        Op::ShlAssign => Op::Shl,
        Op::ShrAssign => Op::Shr,
        Op::AndAssign => Op::BitAnd,
        Op::OrAssign => Op::BitOr,
        Op::XorAssign => Op::BitXor,
        other => unreachable!("compound_base on {other:?}"),
    }
}

fn apply_binary(op: Op, l: i64, r: i64) -> Result<i64, String> {
    Ok(match op {
        Op::Add => l.wrapping_add(r),
        Op::Sub => l.wrapping_sub(r),
        Op::Mul => l.wrapping_mul(r),
        Op::Div => {
            if r == 0 {
                return Err("division by 0".to_string());
            }
            l.wrapping_div(r)
        }
        Op::Mod => {
            if r == 0 {
                return Err("division by 0".to_string());
            }
            l.wrapping_rem(r)
        }
        Op::Shl => l.wrapping_shl(r as u32),
        Op::Shr => l.wrapping_shr(r as u32),
        Op::BitAnd => l & r,
        Op::BitOr => l | r,
        Op::BitXor => l ^ r,
        other => unreachable!("apply_binary on {other:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::{eval, ArithEnv};
    use std::collections::HashMap;

    #[derive(Default)]
    struct MapEnv(HashMap<String, String>);
    impl ArithEnv for MapEnv {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
        fn set(&mut self, name: &str, value: i64) {
            self.0.insert(name.to_string(), value.to_string());
        }
    }

    fn ev(expr: &str) -> i64 {
        let mut env = MapEnv::default();
        eval(expr, &mut env).unwrap_or_else(|e| panic!("eval({expr:?}) failed: {e}"))
    }

    #[test]
    fn precedence_and_parens() {
        assert_eq!(ev("1 + 2 * 3"), 7);
        assert_eq!(ev("(1 + 2) * 3"), 9);
        assert_eq!(ev("2 * 3 + 4 * 5"), 26);
        assert_eq!(ev("10 - 2 - 3"), 5); // left assoc
    }

    #[test]
    fn division_and_modulo() {
        assert_eq!(ev("7 / 2"), 3);
        assert_eq!(ev("7 % 2"), 1);
        assert_eq!(ev("-7 / 2"), -3); // truncation toward zero
    }

    #[test]
    fn number_bases() {
        assert_eq!(ev("0x10"), 16);
        assert_eq!(ev("010"), 8);
        assert_eq!(ev("0"), 0);
    }

    #[test]
    fn unary_and_power() {
        assert_eq!(ev("-2 ** 2"), -4); // ** binds tighter than unary minus
        assert_eq!(ev("2 ** 3 ** 2"), 512); // right associative
        assert_eq!(ev("!0"), 1);
        assert_eq!(ev("!5"), 0);
        assert_eq!(ev("~0"), -1);
    }

    #[test]
    fn comparison_and_logic() {
        assert_eq!(ev("3 > 2"), 1);
        assert_eq!(ev("3 < 2"), 0);
        assert_eq!(ev("1 && 0"), 0);
        assert_eq!(ev("1 || 0"), 1);
        assert_eq!(ev("5 == 5 && 4 != 3"), 1);
    }

    #[test]
    fn bitwise_and_shifts() {
        assert_eq!(ev("6 & 3"), 2);
        assert_eq!(ev("6 | 1"), 7);
        assert_eq!(ev("6 ^ 3"), 5);
        assert_eq!(ev("1 << 4"), 16);
        assert_eq!(ev("256 >> 2"), 64);
    }

    #[test]
    fn ternary_short_circuits() {
        assert_eq!(ev("1 ? 10 : 20"), 10);
        assert_eq!(ev("0 ? 10 : 20"), 20);
        // The dead branch must not error on division by zero.
        assert_eq!(ev("1 ? 5 : 1/0"), 5);
        assert_eq!(ev("0 && 1/0"), 0);
        assert_eq!(ev("1 || 1/0"), 1);
    }

    #[test]
    fn variables_and_assignment() {
        let mut env = MapEnv::default();
        env.0.insert("x".into(), "5".into());
        assert_eq!(eval("x + 1", &mut env).unwrap(), 6);
        assert_eq!(eval("x = x * 2", &mut env).unwrap(), 10);
        assert_eq!(env.0.get("x").unwrap(), "10");
        assert_eq!(eval("x += 5", &mut env).unwrap(), 15);
        assert_eq!(env.0.get("x").unwrap(), "15");
    }

    #[test]
    fn unset_variable_is_zero_and_recursive_values() {
        let mut env = MapEnv::default();
        assert_eq!(eval("y + 1", &mut env).unwrap(), 1); // y unset -> 0
        env.0.insert("a".into(), "b + 1".into());
        env.0.insert("b".into(), "10".into());
        assert_eq!(eval("a", &mut env).unwrap(), 11); // recursive value evaluation
    }

    #[test]
    fn errors() {
        let mut env = MapEnv::default();
        assert!(eval("1/0", &mut env).is_err());
        assert!(eval("1 +", &mut env).is_err());
        assert!(eval("(1 + 2", &mut env).is_err());
        assert!(eval("2 ** -1", &mut env).is_err());
    }
}
