#[allow(dead_code)]
/// Experimental two-tier line scanner — used to test static analysis tooling.
///
/// Scans `lines` for two classes of pattern:
/// - "critical" patterns: must always block (higher priority)
/// - "warning" patterns: should prompt for review (lower priority)
///
/// A critical match on any line must win over a warning match on any other line.
pub fn scan_lines<'a>(lines: &[&'a str]) -> Option<(&'static str, &'a str)> {
    for line in lines {
        let mut warning_match: Option<&str> = None;

        // Critical check — hard block on this line
        if line.contains("CRITICAL") {
            return Some(("block", line));
        }

        // Warning check — set aside for review
        if line.contains("WARNING") {
            warning_match = Some(line);
        }

        // BUG: returns "review" after the first warning on this line,
        // but remaining lines are never checked — a CRITICAL on a later
        // line will be silently skipped.
        //
        // Example:
        //   line 0: "WARNING: unusual path"   → returns "review" here
        //   line 1: "CRITICAL: rm -rf /"      → never reached
        //
        // Fix: hoist warning_match above the outer loop and only emit
        // it after all lines have been processed.
        if let Some(matched) = warning_match {
            return Some(("review", matched));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_on_first_line_blocks() {
        assert_eq!(
            scan_lines(&["CRITICAL: delete everything", "safe line"]),
            Some(("block", "CRITICAL: delete everything"))
        );
    }

    #[test]
    fn warning_only_reviews() {
        assert_eq!(
            scan_lines(&["WARNING: unusual", "safe line"]),
            Some(("review", "WARNING: unusual"))
        );
    }

    /// This test SHOULD pass but currently FAILS due to the priority inversion bug.
    /// A WARNING on line 0 causes early return before CRITICAL on line 1 is checked.
    #[test]
    #[should_panic]
    fn critical_after_warning_must_block_but_does_not() {
        // With the bug: returns ("review", "WARNING...") instead of ("block", "CRITICAL...")
        assert_eq!(
            scan_lines(&["WARNING: unusual path", "CRITICAL: rm -rf /"]),
            Some(("block", "CRITICAL: rm -rf /"))
        );
    }
}
