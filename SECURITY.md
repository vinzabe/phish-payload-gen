# Security Policy

## Reporting a Vulnerability

Report privately to **g@abejar.net**. Do not open a public issue.

## Threat model

`phish-payload-gen` is a **defender-side phishing-awareness
training toolkit**. The pieces:

- a curated library of obviously-fictional lure templates with
  `[PLACEHOLDER]` slots and a `[FAKE-LINK]` marker;
- a phishing detector with nine bundled heuristic rules;
- a difficulty grader (built on top of the detector) that scores
  how subtle a lure is;
- URL/IOC defang/refang helpers;
- an LLM-driven analyst-summary explainer with a citation guard
  that rejects sentences mentioning rule_ids that are not in the
  detection report;
- a `LureGenerator` that gates "realistic" copy behind an
  authorisation check.

## Authorisation gate

The toolkit is configured so that *realistic-looking* lure copy
is produced only when both:

1. the environment variable `AGSBX_RED_TEAM_AUTH=1` is set, and
2. an authorisation file exists at the path named by
   `AGSBX_RED_TEAM_AUTH_FILE` (default `~/.agsbx_red_team_auth`)
   and contains the verbatim statement:

   ```
   I confirm I have written authorisation from the target
   organisation to run a phishing-awareness exercise.
   ```

In any other case the generator returns the bundled training-stub
output, which:

- carries the literal subject prefix `[TRAINING]`;
- contains only the `[FAKE-LINK]` placeholder, never a real URL;
- ends with a footer naming the message as a training stub.

The generator additionally:

- defangs every URL/host that survives the LLM rewrite (so a real
  URL accidentally produced by the LLM cannot be clicked);
- strips any `http(s)://...` token the LLM emits and replaces it
  with `[FAKE-LINK]` before defanging;
- forces the `[TRAINING]` subject prefix even if the LLM dropped
  it.

The 5 LLM_LIVE tests in `tests/test_llm_live.py` exercise *only*
the analyst-side `PhishingExplainer`. The `LureGenerator` is not
tested live.

## Scope and limits

- Detection-only on the defender side. The toolkit does not send
  email, host pages, harvest credentials, or interact with any
  external service.
- Anything you put into an `Email` body may be echoed verbatim
  into the LLM-explainer prompt — strip / hash sensitive fields
  if needed.
- The bundled templates are intentionally clumsy. They are unit
  fixtures, not training material for end users.

## Out of scope

- Bypassing the auth gate by patching `AuthorizationGate.check`
  is, by design, a single line of code. The gate is an
  *organisational* control, not a security boundary.
- Pull requests that remove the `[TRAINING]` subject tag or the
  training footer from the bundled templates.
- Pull requests that weaken the citation guard in
  `PhishingExplainer`.
