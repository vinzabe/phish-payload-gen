# phish-payload-gen

**Phishing-*simulation* content for authorized awareness training — where misuse is made structurally impossible, not merely discouraged.**

This is dual-use, so the guardrails are built into the code rather than written in a policy nobody reads. The difference between an awareness-training tool and phishing infrastructure isn't intent — it's what the code will and won't do:

1. **Refuses to render without a signed authorization.** Authorizations are HMAC-signed; a hand-written approval is rejected as forged.
2. **Only targets verified in-scope domains** from that authorization. An out-of-scope recipient is refused.
3. **Watermarks every artifact** — a visible banner in the body *and* an `X-Phishing-Simulation` header — so it's identifiable as a drill even if it leaks.
4. **Never implements credential capture.** The landing page is educational. There is no `<form>`, no `<input>`, no password field anywhere in the code — asserted by test.

```
$ phishgen generate auth.json --template password-expiry --target alice@corp.example.com
[efd59e3ce4a27daa] to alice@corp.example.com
Subject: Action required: your password expires today
X-Phishing-Simulation: ENG-1
X-Authorized-By: CISO Jane
...

$ phishgen generate auth.json --template password-expiry --target victim@gmail.com
REFUSED: target victim@gmail.com is not in the authorized scope ('corp.example.com',)
```

## The landing page cannot capture anything

This is the line between a training tool and an attack tool. When a recipient clicks, they get an **educational debrief** — what the lure was, which cues to notice — and the click is logged. There is deliberately no code path that renders an input field:

```python
def _landing_page(...):
    """An EDUCATIONAL page. No form, no input field — it debriefs the recipient.
    There is no code path here that accepts a password."""
```

`test_landing_page_has_no_credential_form` scans the rendered HTML for `<form>`, `<input>`, `type="password"`, and `credential` and fails if any appear. A tool that *could* capture credentials is phishing infrastructure with a disclaimer; this one cannot.

## Results feed training, not discipline

Click rates are reported per engagement and are explicitly framed as input to **awareness-training assignment**, never punishment. The click log records that a click happened and shows the educational page — it captures nothing about the person beyond the fact of the click.

## Authorized use only

Run this only against an organization you are authorized to test, under a written engagement. The signed-authorization gate exists to make that authorization a technical precondition, not an honor-system checkbox — you literally cannot generate an artifact without one, and it must name an approver, a scope, and an expiry.

## Quickstart (60 seconds)

```bash
git clone https://github.com/vinzabe/phish-payload-gen && cd phish-payload-gen
python -m pip install -e ".[dev]"
export PHISHGEN_SECRET=your-signing-secret

# 1. a signed authorization (an approver, a scope, an expiry)
phishgen authorize --engagement ENG-1 --approver "CISO Jane" \
    --scope corp.example.com --expires 2027-01-01 > auth.json

# 2. generate for an IN-SCOPE target (out-of-scope is refused)
phishgen generate auth.json --template password-expiry --target alice@corp.example.com

# 3. record a click (shows the educational page) and report
phishgen click <tracking-id>
phishgen report --engagement ENG-1
```

Exit codes for `generate`: `0` generated, `3` **refused** (no/invalid auth or out-of-scope), `1` error.

## Development

```bash
python -m pip install -e ".[dev]"
pytest --cov=phishgen      # 26 tests, ~96% coverage
mypy --strict src/phishgen # clean
ruff check src tests       # clean
```

## License

MIT © vinzabe
