"""browser_credentials skill — Firefox saved-login recovery + the analysis
helpers that turn recovered logins into findings (password reuse, covert/
secondary identity). The NSS decrypt itself is exercised crash-safely; the
helpers are pure and deterministic."""
from pathlib import Path

from el.skills import browser_credentials as bc
from el.skills.browser_credentials import FirefoxLogin


def _logins(pairs):
    return [FirefoxLogin(origin=o, username=u, password=p) for o, u, p in pairs]


# --- password reuse --------------------------------------------------------

def test_password_reuse_detects_shared_password():
    logins = _logins([
        ("https://accounts.google.com", "redguard.cobra@gmail.com", "C0bracommand"),
        ("https://login.live.com", "fred.rocba@outlook.com", "C0bracommand"),
        ("https://www.netflix.com", "fred.rocba@gmail.com", "C0bracommand"),
        ("https://uniq.example", "x@example.com", "different"),
    ])
    reuse = bc.password_reuse(logins)
    assert "C0bracommand" in reuse
    assert len(reuse["C0bracommand"]) == 3
    assert "different" not in reuse  # used once -> not reuse


def test_password_reuse_empty_when_all_unique():
    logins = _logins([("a", "u1", "p1"), ("b", "u2", "p2")])
    assert bc.password_reuse(logins) == {}


# --- covert / alternate identity ------------------------------------------

def test_find_alternate_identity_flags_mismatched_localpart():
    logins = _logins([
        ("https://www.netflix.com", "fred.rocba@gmail.com", "x"),
        ("https://login.live.com", "fred.rocba@outlook.com", "x"),
        ("https://www.amazon.com", "fred.rocba@gmail.com", "x"),
        ("https://accounts.google.com", "redguard.cobra@gmail.com", "x"),  # covert
    ])
    alts = bc.find_alternate_identities(logins)
    assert alts == ["redguard.cobra@gmail.com"]


def test_find_alternate_identity_none_when_consistent_owner():
    logins = _logins([
        ("https://a", "fred.rocba@gmail.com", "x"),
        ("https://b", "fred.rocba@outlook.com", "x"),
    ])
    assert bc.find_alternate_identities(logins) == []


def test_find_alternate_identity_ignores_non_email_usernames():
    # facebook username is a phone number -> not an email -> not flagged
    logins = _logins([
        ("https://a", "fred.rocba@gmail.com", "x"),
        ("https://b", "fred.rocba@outlook.com", "x"),
        ("https://facebook.com", "3392233317", "x"),
    ])
    assert bc.find_alternate_identities(logins) == []


# --- crash safety ----------------------------------------------------------

def test_decrypt_firefox_is_crash_safe_on_missing_profile(tmp_path):
    """A missing/incomplete profile must return ok=False, never raise or
    crash the parent (NSS runs in an isolated subprocess)."""
    r = bc.decrypt_firefox(tmp_path / "nope")
    assert r.ok is False
    assert r.error and "logins.json" in r.error
    assert r.logins == []


def test_decrypt_firefox_crash_safe_on_garbage_profile(tmp_path):
    """A logins.json + a junk key4.db (which can make libnss abort) must be
    contained by the subprocess and surface as ok=False, not a segfault in
    the parent."""
    (tmp_path / "logins.json").write_text('{"logins": []}')
    (tmp_path / "key4.db").write_bytes(b"not a real nss db" * 8)
    r = bc.decrypt_firefox(tmp_path)
    assert r.ok is False        # parent survived; failure reported, not crashed
    assert r.logins == []


def test_is_firefox_profile(tmp_path):
    assert not bc.is_firefox_profile(tmp_path)
    (tmp_path / "logins.json").write_text("{}")
    (tmp_path / "key4.db").write_bytes(b"x")
    assert bc.is_firefox_profile(tmp_path)


def test_as_evidence_carries_provenance(tmp_path):
    from el.skills.browser_credentials import FirefoxCredsResult
    r = FirefoxCredsResult(profile_dir=tmp_path, ok=True, primary_password_set=False,
                           saved_count=2, logins=_logins([("h", "u@e.com", "p")]))
    ev = r.as_evidence(facts={"origins": ["h"]})
    assert ev.tool.startswith("libnss3")
    assert ev.extracted_facts["saved_logins"] == 2
    assert ev.extracted_facts["primary_password_set"] is False
