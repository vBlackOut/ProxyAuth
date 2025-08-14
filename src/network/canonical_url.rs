

#[inline]
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => 10 + (b - b'a'),
        b'A'..=b'F' => 10 + (b - b'A'),
        _ => 0xFF,
    }
}

#[inline]
fn finalize_segment(out: &mut Vec<u8>, seg: &mut Vec<u8>, stack: &mut Vec<usize>) {
    if seg.is_empty() {
        return;
    }
    if seg == b"." {
        // no-op
    } else if seg == b".." {
        if let Some(pos) = stack.pop() {
            out.truncate(pos);
        } else {
        }
    } else {
        if *out.last().unwrap_or(&b'/') != b'/' {
            out.push(b'/');
        }
        let start = out.len();
        stack.push(start);
        out.extend_from_slice(&*seg);
    }
    seg.clear();
}

pub fn canonicalize_path_for_match(raw: &str) -> String {
    let bytes = raw.as_bytes();

    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 2);
    out.push(b'/');

    let mut seg: Vec<u8> = Vec::with_capacity(16);
    let mut stack: Vec<usize> = Vec::with_capacity(8);

    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];

        if b == b'/' || b == b'\\' {
            finalize_segment(&mut out, &mut seg, &mut stack);
            if *out.last().unwrap_or(&b'/') != b'/' {
                out.push(b'/');
            }
            i += 1;
            continue;
        }

        if b == b'%' && i + 2 < bytes.len() {
            let h1 = hex_val(bytes[i + 1]);
            let h2 = hex_val(bytes[i + 2]);
            if h1 != 0xFF && h2 != 0xFF {
                let dec = (h1 << 4) | h2;
                if dec == b'/' || dec == b'\\' {
                    finalize_segment(&mut out, &mut seg, &mut stack);
                    if *out.last().unwrap_or(&b'/') != b'/' {
                        out.push(b'/');
                    }
                } else {
                    seg.push(dec);
                }
                i += 3;
                continue;
            }
        }

        seg.push(b);
        i += 1;
    }

    finalize_segment(&mut out, &mut seg, &mut stack);

    if out.len() > 1 && out.last() == Some(&b'/') {
        out.pop();
    }

    String::from_utf8(out).unwrap_or_else(|_| "/".to_string())
}

#[cfg(test)]
mod tests {
    use super::canonicalize_path_for_match;

    #[test]
    fn empty_and_root() {
        assert_eq!(canonicalize_path_for_match(""), "/");
        assert_eq!(canonicalize_path_for_match("/"), "/");
    }

    #[test]
    fn collapses_slashes_and_backslashes() {
        assert_eq!(canonicalize_path_for_match("///a//b\\c"), "/a/b/c");
        assert_eq!(canonicalize_path_for_match("\\\\a\\\\b\\\\c\\"), "/a/b/c");
    }

    #[test]
    fn removes_trailing_slash_except_root() {
        assert_eq!(canonicalize_path_for_match("/a/b/"), "/a/b");
        assert_eq!(canonicalize_path_for_match("/a/"), "/a");
        assert_eq!(canonicalize_path_for_match("/"), "/");
    }

    #[test]
    fn dot_and_dotdot_segments() {
        // "." no-op
        assert_eq!(canonicalize_path_for_match("/a/./b/./c"), "/a/b/c");
        // ".." move
        assert_eq!(canonicalize_path_for_match("/a/b/../c"), "/a/c");
        assert_eq!(canonicalize_path_for_match("/../../x"), "/x");
        assert_eq!(canonicalize_path_for_match("/../.."), "/");
    }

    #[test]
    fn percent_decoded_slashes_are_treated_as_separators() {
        // %2f and %2F replace by '/'
        assert_eq!(canonicalize_path_for_match("/api%2fadmin"), "/api/admin");
        assert_eq!(canonicalize_path_for_match("/api%2Fadmin"), "/api/admin");
        // begin
        assert_eq!(canonicalize_path_for_match("/%2F"), "/");
    }

    #[test]
    fn percent_decoded_dots_affect_segments() {
        assert_eq!(canonicalize_path_for_match("/a/%2E/b"), "/a/b");      // "." no-op
        assert_eq!(canonicalize_path_for_match("/a/%2e/b"), "/a/b");
        assert_eq!(canonicalize_path_for_match("/a/%2E%2E/b"), "/b");     // ".." move
        assert_eq!(canonicalize_path_for_match("/a/%2e%2e/b"), "/b");
    }

    #[test]
    fn invalid_percent_sequences_are_left_literal() {
        assert_eq!(canonicalize_path_for_match("/a%2"), "/a%2");
        assert_eq!(canonicalize_path_for_match("/a%G0"), "/a%G0");
        assert_eq!(canonicalize_path_for_match("/a%zzb"), "/a%zzb");
    }

    #[test]
    fn idempotent_on_canonical_output() {
        let cases = [
            "/a/b/c",
            "/a/b",
            "/",
            "/api/admin",
            "/a-b_c.1",
        ];
        for &p in &cases {
            assert_eq!(canonicalize_path_for_match(p), p);
            let once = canonicalize_path_for_match(p);
            let twice = canonicalize_path_for_match(&once);
            assert_eq!(once, twice);
        }
    }

    #[test]
    fn mixed_case_and_windowsy_paths() {
        assert_eq!(canonicalize_path_for_match("/A\\B\\..\\C/./D"), "/A/C/D");
        assert_eq!(canonicalize_path_for_match("/A%2Fb\\C%2fD"), "/A/b/C/D");
    }

    #[test]
    fn percent_decoded_slash_is_separator() {
        assert_eq!(canonicalize_path_for_match("/api%2Fadmin"), "/api/admin");
        assert_eq!(canonicalize_path_for_match("/api%5Cadmin"), "/api/admin");
    }

    #[test]
    fn dot_and_dotdot() {
        assert_eq!(canonicalize_path_for_match("/a/./b/../c"), "/a/c");
        assert_eq!(canonicalize_path_for_match("/././"), "/");
    }

    #[test]
    fn windowsy_and_trailing_slash() {
        assert_eq!(canonicalize_path_for_match(r"\A\B\C"), "/A/B/C");
        assert_eq!(canonicalize_path_for_match("/A/B/C/"), "/A/B/C");
    }

    #[test]
    fn preserve_case_of_non_separators() {
        // la fonction NE minuscule pas le contenu, elle ne touche que les séparateurs
        assert_eq!(canonicalize_path_for_match("/A/b/C/D"), "/A/b/C/D");
    }
}
