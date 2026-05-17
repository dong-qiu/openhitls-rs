use std::fmt::{self, Write};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct TestCase {
    pub line: usize,
    pub tc_name: String,
    pub args: Vec<Arg>,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Arg {
    Hex(Vec<u8>),
    /// A quoted field whose body is not valid hex — e.g. a file path
    /// (`"../testdata/cert/foo.der"`) in the PKI SDV `.data` files.
    Str(String),
    Symbol(String),
}

impl Arg {
    pub fn as_hex(&self) -> Option<&[u8]> {
        match self {
            Arg::Hex(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_symbol(&self) -> Option<&str> {
        match self {
            Arg::Symbol(s) => Some(s),
            _ => None,
        }
    }

    /// The text of a quoted non-hex field (`Arg::Str`).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Arg::Str(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ParseError {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for ParseError {}

pub fn parse_data_file(path: &Path) -> Result<Vec<TestCase>, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let mut cases = Vec::new();
    let mut pending_description: Option<String> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            // Blank line resets the pending description so it never spans cases.
            pending_description = None;
            continue;
        }

        if !trimmed.starts_with("SDV_") || !looks_like_tc_line(trimmed) {
            pending_description = Some(trimmed.to_string());
            continue;
        }

        // Lenient: a row whose args fail to parse (e.g. odd-length hex in a
        // non-KAT C case such as `DSA_GEN_G_FUNC_TC004`) is still recorded
        // with its TC name and empty args, so the per-algorithm classifier
        // routes it to `ApiSurface`/`Unknown` instead of aborting the whole
        // file. A genuinely malformed KAT row would surface as a skipped
        // case in the generation summary rather than silently vanishing.
        let (tc_name, args) = match parse_tc_line(trimmed, line_no) {
            Ok(v) => v,
            Err(_) => (
                trimmed.split(':').next().unwrap_or(trimmed).to_string(),
                Vec::new(),
            ),
        };
        cases.push(TestCase {
            line: line_no,
            tc_name,
            args,
            description: pending_description.take(),
        });
    }

    Ok(cases)
}

/// A real TC line is either bare `SDV_X` or `SDV_X:...` (TC name
/// immediately followed by `:`). Description lines in the C `.data`
/// format also start with `SDV_X` but have additional words separated
/// by whitespace (e.g. `SDV_X CRYPT_MAC_HMAC_SHA1 init test`). This
/// helper rejects those by checking whether whitespace appears before
/// the first `:`.
fn looks_like_tc_line(line: &str) -> bool {
    let mut chars = line.chars();
    for c in chars.by_ref() {
        if c == ':' {
            // A real TC line packs its args against the colon
            // (`SDV_X:"hex"` / `SDV_X:SYMBOL`). Some `.data` files also
            // carry description lines in the form `SDV_X: human text` —
            // a colon followed by whitespace — which must NOT be parsed
            // as a TC line.
            return !matches!(chars.next(), Some(n) if n.is_whitespace());
        }
        if c.is_whitespace() {
            return false;
        }
    }
    true
}

fn parse_tc_line(line: &str, line_no: usize) -> Result<(String, Vec<Arg>), ParseError> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;

    for c in line.chars() {
        match c {
            '"' => {
                in_quote = !in_quote;
                current.push(c);
            }
            ':' if !in_quote => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    if in_quote {
        return Err(ParseError {
            line: line_no,
            msg: "unterminated quoted hex literal".into(),
        });
    }
    fields.push(current);

    if fields.is_empty() {
        return Err(ParseError {
            line: line_no,
            msg: "empty TC line".into(),
        });
    }

    // A trailing `:` (e.g. `SDV_X:` for a no-arg TC) leaves an empty
    // last field after split — drop it so it isn't mistaken for an
    // empty arg.
    while fields.len() > 1 && fields.last().map(|s| s.trim().is_empty()) == Some(true) {
        fields.pop();
    }

    let tc_name = fields.remove(0).trim().to_string();
    let mut args = Vec::with_capacity(fields.len());
    for (i, raw) in fields.iter().enumerate() {
        let field = raw.trim();
        if field.starts_with('"') && field.ends_with('"') {
            let body = &field[1..field.len() - 1];
            // A quoted field is hex if it decodes cleanly; otherwise it is
            // a string literal (a file path, a format token in quotes, …).
            match parse_hex(body) {
                Ok(bytes) => args.push(Arg::Hex(bytes)),
                Err(_) => args.push(Arg::Str(body.to_string())),
            }
        } else if field.is_empty() {
            return Err(ParseError {
                line: line_no,
                msg: format!("arg #{} is empty (use \"\" for empty hex)", i + 1),
            });
        } else {
            args.push(Arg::Symbol(field.to_string()));
        }
    }

    Ok((tc_name, args))
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length {}", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])
            .ok_or_else(|| format!("non-hex byte '{}' at index {i}", bytes[i] as char))?;
        let lo = hex_nibble(bytes[i + 1])
            .ok_or_else(|| format!("non-hex byte '{}' at index {}", bytes[i + 1] as char, i + 1))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Format a byte slice as a Rust `&[u8]` array literal expression.
/// Used by emitters to inline test inputs/expected outputs without
/// pulling in a runtime hex decoder.
pub fn format_byte_slice(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "&[]".to_string();
    }
    let mut s = String::from("&[\n");
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            s.push_str("    ");
        }
        write!(s, "0x{b:02x}, ").unwrap();
        if i % 16 == 15 {
            s.push('\n');
        }
    }
    if bytes.len() % 16 != 0 {
        s.push('\n');
    }
    s.push(']');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_kat_line() {
        let line = r#"SDV_CRYPT_EAL_MD_SHA2_FUNC_TC003:CRYPT_MD_SHA256:"d3":"28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1""#;
        let (name, args) = parse_tc_line(line, 1).unwrap();
        assert_eq!(name, "SDV_CRYPT_EAL_MD_SHA2_FUNC_TC003");
        assert_eq!(args.len(), 3);
        assert_eq!(args[0].as_symbol(), Some("CRYPT_MD_SHA256"));
        assert_eq!(args[1].as_hex(), Some(&[0xd3][..]));
        assert_eq!(args[2].as_hex().unwrap().len(), 32);
    }

    #[test]
    fn parses_empty_hex() {
        let line = r#"SDV_X:"":"abcd""#;
        let (_, args) = parse_tc_line(line, 1).unwrap();
        assert_eq!(args[0].as_hex(), Some(&[][..]));
        assert_eq!(args[1].as_hex(), Some(&[0xab, 0xcd][..]));
    }

    #[test]
    fn rejects_odd_hex_length() {
        let line = r#"SDV_X:"abc""#;
        assert!(parse_tc_line(line, 42).is_err());
    }

    #[test]
    fn rejects_description_line_with_space() {
        // C .data has description lines that start with `SDV_X` but
        // contain spaces — those must NOT be parsed as TC lines.
        assert!(!looks_like_tc_line(
            "SDV_CRYPT_EAL_HMAC_API_TC002 CRYPT_MAC_HMAC_SHA1 init test"
        ));
        assert!(looks_like_tc_line("SDV_X:arg1:arg2"));
        assert!(looks_like_tc_line("SDV_X:"));
        assert!(looks_like_tc_line("SDV_X"));
    }

    #[test]
    fn format_byte_slice_empty() {
        assert_eq!(format_byte_slice(&[]), "&[]");
    }

    #[test]
    fn format_byte_slice_small() {
        let formatted = format_byte_slice(&[0xde, 0xad]);
        assert!(formatted.contains("0xde"));
        assert!(formatted.contains("0xad"));
    }
}
