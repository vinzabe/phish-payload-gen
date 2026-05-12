# phish-payload-gen

Defender-side phishing-awareness training toolkit. Bundled
template library, nine-rule heuristic detector, LLM-grounded
analyst explainer, URL/IOC defanger, lure-difficulty grader, and
an authorisation-gated `LureGenerator` that returns clearly-marked
training stubs unless an explicit authorisation file is in place.

This project is **not** a phishing campaign tool. It does not send
email, host pages, harvest credentials, or talk to any external
service other than the optional LLM explainer.

## Layout

- `phish_paygen.email` — `Email` model.
- `phish_paygen.defang` — `defang`, `defang_url`, `refang`.
- `phish_paygen.templates` — `LureTemplate`, `TemplateLibrary`,
  six bundled topics (`invoice`, `package_delivery`,
  `password_reset`, `payroll`, `hr_policy`, `oauth_consent`).
- `phish_paygen.rules` — `PhishingRule` plus the bundled rules:
  `DisplayFromMismatch`, `LookalikeDomain`,
  `UrgentActionLanguage`, `SuspiciousLink`, `MismatchedLinkText`,
  `AttachmentB64Suspicious`, `SuspiciousReplyTo`, `TooManyLinks`,
  `UnsignedExternalSender`, plus `default_rules()`.
- `phish_paygen.detector` — `PhishingDetector`,
  `DetectionReport`.
- `phish_paygen.difficulty` — `DifficultyGrader`,
  `DifficultyLabel`.
- `phish_paygen.auth` — `AuthorizationGate`,
  `AuthorizationStatus`.
- `phish_paygen.generator` — `LureGenerator`, `GeneratedLure`.
- `phish_paygen.explain` — `PhishingExplainer` with citation
  guard.
- `phish_paygen.cli` — `phish-paygen list-templates`, `generate`,
  `detect`, `grade`, `defang`, `refang`, `auth-status`.

## Quick start

```python
from phish_paygen import (
    Email, PhishingDetector, DifficultyGrader,
    LureGenerator, defang)

# Detect.
e = Email(
    subject="URGENT: verify your PayPal account",
    from_addr="security@paypaI-secure.zip",
    from_name="PayPal Security",
    reply_to="paypal-help@gmail.com",
    body_text="click http://192.168.1.1/login")
report = PhishingDetector().analyze(e)
print(report.band, report.score)
for h in report.hits:
    print(" ", h.severity, h.rule_id)

# Grade lure subtlety.
print(DifficultyGrader().grade(e).label)

# Render a stub training lure.
out = LureGenerator().generate(
    "PWD-001",
    {"FIRST_NAME": "Alice", "COMPANY": "Acme",
     "HOURS": "24"})
print(out.realistic, out.subject, out.body[:80])

# Defang an URL.
print(defang("visit https://example.com/login"))
```

## Authorisation gate

`LureGenerator` returns the bundled `[TRAINING]`-tagged stub copy
unless **both** are true:

1. `AGSBX_RED_TEAM_AUTH=1` in the environment, and
2. `~/.agsbx_red_team_auth` (override with
   `AGSBX_RED_TEAM_AUTH_FILE`) contains the verbatim statement:

   ```
   I confirm I have written authorisation from the target
   organisation to run a phishing-awareness exercise.
   ```

Even when both are present the toolkit:

- forces the `[TRAINING]` subject prefix;
- strips any URL the LLM produces and replaces it with
  `[FAKE-LINK]`;
- defangs every host that survives the rewrite;
- appends a training-banner footer.

See `SECURITY.md` for the full threat model.

## CLI

```sh
python3 -m phish_paygen.cli list-templates
python3 -m phish_paygen.cli generate \
    --template-id PWD-001 \
    --values '{"FIRST_NAME":"Alice","COMPANY":"Acme","HOURS":"24"}'
python3 -m phish_paygen.cli detect --input email.json
python3 -m phish_paygen.cli grade --input email.json
python3 -m phish_paygen.cli defang "visit https://x.com"
python3 -m phish_paygen.cli auth-status
```

`email.json` is the `Email.from_dict(...)` shape:

```json
{
  "subject": "URGENT verify now",
  "from_addr": "x@evil.test",
  "from_name": "PayPal",
  "body_text": "click http://1.2.3.4/x",
  "body_html": "<a href=\"http://bad.zip/x\">https://paypal.com</a>"
}
```

## Tests

```sh
pip install -r requirements.txt
python3 -m pytest tests/ -q                # 148 mocked tests
LLM_LIVE=1 python3 -m pytest tests/test_llm_live.py -q  # 5 live
```

The 5 LLM_LIVE tests exercise *only* the analyst-side
`PhishingExplainer`. The `LureGenerator` is **not** tested live —
realistic generation is locked behind the auth gate by design.

## Scope

- Detection-only. The toolkit does not collect any telemetry on
  its own; you bring the email.
- Anything you feed into `Email` may be echoed verbatim into the
  LLM-explainer prompt — strip / hash sensitive fields if needed.
- The bundled templates are intentionally clumsy. They are unit
  fixtures, not training material for end users.
