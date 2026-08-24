# Threat model, scope & authorized-use statement

## What this is
A generator for **authorized** phishing-simulation (awareness-training) content,
built so that misuse requires writing new code rather than changing a setting.

## Authorized use only
Use this only against an organization you are authorized to test, under a written
engagement. The signed-authorization gate makes that a technical precondition: you
cannot generate an artifact without a valid authorization naming an approver, a
scope, and an expiry. Only in-scope domains can be targeted.

## The structural guarantees
- **No render without a valid, in-scope, unexpired, signed authorization.**
- **No credential capture** — the landing page has no form/input, enforced by test.
- **Every artifact watermarked** (visible + header).
- **Click log captures nothing** about the person beyond the fact of a click.

## Trust boundaries
- **The signing secret is the control.** Anyone with it can mint authorizations, so
  it must be held only by those permitted to approve engagements. The CLI takes it
  via env, never a flag default.
- **Delivery is out of scope.** This generates content and tracks clicks; it does
  not send mail. That boundary is deliberate — sending is where authorization and
  rate/consent controls in your mail platform apply.

## Limits, stated plainly
- **It measures clicks, not credential entry.** Measuring whether a user would have
  typed a password requires building capture, which this tool refuses to do. Click
  rate is the safe proxy.
- **HMAC authorization is integrity, not workflow.** It proves an authorization was
  signed by the secret holder; it does not implement multi-party approval or
  revocation. Pair with your real change-approval process.
- **Watermarks assume the artifact is used as generated.** Someone who strips the
  watermark before sending has left the intended workflow — but note they would
  still have no credential-capture capability from this tool.
- **Templates are illustrative.** They teach recognition; they are not a
  comprehensive lure library, by design.

## Non-goals (things this deliberately will NOT do)
- Capture credentials or any recipient input.
- Send email.
- Generate content for unauthorized or out-of-scope targets.
- Support punitive/name-and-shame reporting.

## Reporting
Any path that renders without a valid authorization, targets out of scope, or
produces an artifact that could capture input is a critical bug — report to
**gabejar@usa.com**.
