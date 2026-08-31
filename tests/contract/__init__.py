"""SDK-side contract tests — replay committed goldens through the REAL SDK.

Runs in the SDK venv (publish gate + pre-push ci.sh step). Loads the same golden
envelopes the server side writes and replays each through the public SDK method
/ model, asserting the status→model dispatch that shipped broken in 0.6.1. Never
imports the backend ``rine``.
"""
