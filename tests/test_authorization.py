import datetime as dt

import pytest

from phishgen.authorization import Authorization, AuthorizationError

TODAY = dt.date(2026, 8, 24)


def _auth(**kw):
    base = dict(engagement_id="E1", approver="Jane",
                scope_domains=("corp.example.com",), expires=dt.date(2027, 1, 1))
    base.update(kw)
    return Authorization(**base)


def test_unsigned_is_rejected():
    with pytest.raises(AuthorizationError, match="unsigned"):
        _auth().verify("s", today=TODAY)


def test_valid_signature_accepted():
    _auth().sign("s").verify("s", today=TODAY)   # no raise


def test_forged_signature_rejected():
    signed = _auth().sign("real")
    with pytest.raises(AuthorizationError, match="invalid"):
        signed.verify("forged", today=TODAY)


def test_tampered_scope_rejected():
    signed = _auth().sign("s")
    tampered = Authorization(signed.engagement_id, signed.approver,
                             ("gmail.com",), signed.expires, signed.signature)
    with pytest.raises(AuthorizationError, match="invalid"):
        tampered.verify("s", today=TODAY)


def test_expired_rejected():
    signed = _auth(expires=dt.date(2025, 1, 1)).sign("s")
    with pytest.raises(AuthorizationError, match="expired"):
        signed.verify("s", today=TODAY)


def test_empty_scope_rejected():
    signed = _auth(scope_domains=()).sign("s")
    with pytest.raises(AuthorizationError, match="no in-scope"):
        signed.verify("s", today=TODAY)


def test_permits_in_scope_including_subdomains():
    a = _auth(scope_domains=("corp.example.com",))
    assert a.permits_target("alice@corp.example.com")
    assert a.permits_target("bob@sub.corp.example.com")


def test_rejects_out_of_scope():
    a = _auth(scope_domains=("corp.example.com",))
    assert not a.permits_target("victim@gmail.com")
    assert not a.permits_target("x@notcorp.example.com.evil.com")
