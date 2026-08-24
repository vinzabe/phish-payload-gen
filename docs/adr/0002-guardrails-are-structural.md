# 2. Make misuse structurally impossible, not policy-discouraged

Date: 2026-08-24
Status: Accepted

## Context
A phishing-simulation generator is dual-use. The honest question is not "do we
trust the user" but "what can this code be turned into". A generator that can
render a credential-capture page is phishing infrastructure; a disclaimer does not
change that.

## Decision
Four guardrails, each enforced by code and covered by tests:
1. **Signed authorization required.** `generate` calls `Authorization.verify`,
   which rejects unsigned, forged, tampered, and expired authorizations. No render
   without it.
2. **Scope enforcement.** The target's domain must be in the authorization's scope;
   out-of-scope targets raise and return CLI exit 3.
3. **Mandatory watermarking.** Every artifact carries a visible banner and an
   `X-Phishing-Simulation` header; `Artifact.is_watermarked` and a test enforce it.
4. **No credential capture, by construction.** The landing page renderer contains
   no form/input. A test scans the output for `<form>`, `<input>`,
   `type="password"`, and `credential`.

## Consequences
- Turning this into a real phishing kit requires *writing new code*, not flipping a
  flag — which is the strongest signal of the tool's intent.
- The signed authorization makes "who approved this" a technical precondition with a
  named approver, not an honor-system field.
- Cost: it cannot run an unauthorized or ad-hoc test, and it cannot measure whether
  a user would have *entered* credentials (only whether they clicked). Both are
  deliberate — measuring credential entry requires building capture, which is the
  one thing this tool refuses to do.
