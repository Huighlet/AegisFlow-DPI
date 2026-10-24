"""
Unit tests for the streaming Aho-Corasick multi-pattern signature matcher.
"""

from aegisflow.matcher import AhoCorasickMatcher


def test_aho_corasick_single_and_multiple_matches():
    """Verify searching multiple signatures across a single byte stream in linear time."""
    matcher = AhoCorasickMatcher()
    matcher.add_pattern(b"powershell", "PowerShell Execution")
    matcher.add_pattern(b"cmd.exe", "CMD Execution")
    matcher.add_pattern(b"whoami", "Privilege Reconnaissance")
    matcher.build_automaton()

    payload = b"GET /run?exec=cmd.exe%20whoami%20powershell HTTP/1.1"
    matches = matcher.search(payload)

    matched_sigs = [sig for offset, sig in matches]
    assert "CMD Execution" in matched_sigs
    assert "Privilege Reconnaissance" in matched_sigs
    assert "PowerShell Execution" in matched_sigs
    assert len(matches) == 3


def test_aho_corasick_overlapping_patterns():
    """Verify overlapping matches are both detected."""
    matcher = AhoCorasickMatcher()
    matcher.add_pattern(b"she", "She")
    matcher.add_pattern(b"he", "He")
    matcher.add_pattern(b"hers", "Hers")
    matcher.build_automaton()

    matches = matcher.search(b"ushers")
    matched_sigs = [sig for offset, sig in matches]
    assert "She" in matched_sigs
    assert "He" in matched_sigs
    assert "Hers" in matched_sigs


def test_no_matches_clean():
    """Verify clean payload produces zero false positives."""
    matcher = AhoCorasickMatcher()
    matcher.add_pattern(b"malware_signature", "Malware Sig")
    matcher.build_automaton()

    assert matcher.search(b"completely benign harmless corporate traffic") == []
