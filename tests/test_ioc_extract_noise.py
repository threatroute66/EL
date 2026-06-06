

def test_url_and_winpath_split_at_control_bytes():
    """Memory-carved strings are NUL-padded; \\S-style negated classes
    matched \\x00 so adjacent carved URLs fused into one IOC with
    embedded NULs (327 of them poisoned the Rocba case.html — grep
    flips to binary-file mode on the report). Control bytes must
    terminate the token."""
    from el.skills.ioc_extract import extract

    blob = ("https://a.example.com/one\x00\x00\x00\x00"
            "https://b.example.com/two\x01C:\\Users\\x\\evil.exe\x00"
            "C:\\Temp\\b.dll")
    out = extract(blob)
    assert "https://a.example.com/one" in out["url"]
    assert "https://b.example.com/two" in out["url"]
    assert all("\x00" not in u and "\x01" not in u for u in out["url"])
    assert all("\x00" not in p for p in out.get("winpath", set()))
