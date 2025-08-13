

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
