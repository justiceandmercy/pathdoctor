from pathdoctor.audit import audit, parse_entries, shadowed_binaries


def test_parse_entries():
    assert parse_entries("/a:/b") == ["/a", "/b"]


def test_audit_clean():
    import os
    import tempfile

    d = tempfile.mkdtemp()
    findings = audit(f"{d}:{d}")
    assert findings["missing"] == []
    assert findings["duplicates"] == [d]


def test_audit_missing():
    findings = audit("/no/such/dir:/another/missing")
    assert len(findings["missing"]) == 2


def test_empty_entry():
    findings = audit("/usr/bin:")
    assert findings["empty"] == [""]


def test_shadowed():
    import os
    import tempfile

    a = tempfile.mkdtemp()
    b = tempfile.mkdtemp()
    name = "demo"
    for d in (a, b):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(p, 0o755)
    shadow = shadowed_binaries([a, b])
    assert name in shadow
    assert shadow[name] == [a, b]
