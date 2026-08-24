# 3. Clicks feed training assignment, and capture nothing about the person

Date: 2026-08-24
Status: Accepted

## Context
Phishing simulations can harm the culture they aim to improve if results are used
to punish employees or if the click log becomes a surveillance record. Both are
avoidable design choices.

## Decision
- A click records only that a click occurred against a tracking id, plus a
  timestamp. No user identifier beyond the target the engagement already knew, no
  browser/IP capture, nothing the recipient typed (they cannot type anything).
- Reporting is per-engagement click rate, framed in output as input to TRAINING
  assignment, not discipline.
- Unknown tracking ids are ignored (`record_click` returns False), so a random
  probe cannot manufacture results.

## Consequences
- The tool produces the one metric awareness programs need (who needs training)
  without the data that makes simulations resented.
- It cannot support a "name and shame" workflow, which is intentional.
