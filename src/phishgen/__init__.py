"""phishgen — phishing-SIMULATION content for authorized awareness training.

This is dual-use, so the constraints are designed in rather than requested. The
difference between an awareness-training tool and phishing infrastructure is not
intent — it is what the code will and will not do:

  * It **refuses to render** without a signed authorization reference.
  * It only targets **verified in-scope** domains from that authorization.
  * Every artifact is **watermarked** as a simulation (visible + embedded).
  * It **never implements credential capture.** The training landing page logs the
    click and shows an educational message. There is no field that accepts a
    password, by construction — asserted by test.

A tool that could capture credentials is phishing infrastructure with a disclaimer.
This one cannot, which is the point.
"""
__version__ = "1.0.0"
