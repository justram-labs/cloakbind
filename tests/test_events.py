"""Unit tests for the recent-events buffer and account-name masking."""

from cloakbind.events import EventLog, mask_account

D = "\u2022\u2022\u2022"


def test_mask_formats():
    assert mask_account("jdoe@corp.example.com") == "j" + D + "e@corp.example.com"
    assert mask_account("CORP\\jdoe") == "CORP\\j" + D + "e"
    assert mask_account("CN=John Doe,OU=Users,DC=corp,DC=example,DC=com") == "CN=J" + D + "e,OU=Users,DC=corp,DC=example,DC=com"
    assert mask_account("jdoe") == "j" + D + "e"
    assert mask_account("ab") == "\u2022\u2022"
    assert mask_account("(anonymous)") == "(anonymous)"
    assert mask_account("") == ""
    # same mask length regardless of name length
    assert mask_account("averyveryverylongname") == "a" + D + "e"


def test_ring_buffer_newest_first_and_bounded():
    log = EventLog(size=10)
    for i in range(25):
        log.add("bind_ok", account="user%02d@x.local" % i)
    snap = log.snapshot(show_account_names=True)
    assert len(snap) == 10
    assert snap[0]["account"] == "user24@x.local" and snap[-1]["account"] == "user15@x.local"
    assert log.snapshot()[0]["account"].startswith("u" + D)
    assert snap[0]["level"] == "ok" and snap[0]["label"] == "Signed in"
