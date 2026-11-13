"""The group-reason renderer: ``org_rule`` has its clause and an unknown token cannot raise.

The twin of ``rine-core/src/group-admission.ts``; the byte-for-byte
binding to that map is asserted on the TypeScript side, which reads this file.
"""

from __future__ import annotations

from rine.admission_words import group_admission_skip_sentence


class TestGroupAdmissionSkipSentence:
    def test_an_org_rule_skip_names_the_rule_not_the_token(self):
        sentence = group_admission_skip_sentence("org_rule")

        assert sentence.startswith("refused by an organisation's group rule:")
        assert "not recognised" not in sentence

    def test_an_unknown_token_is_quoted_back_rather_than_raised(self):
        assert (
            group_admission_skip_sentence("some_future_reason")
            == "reason not recognised by this client: some_future_reason"
        )

    def test_no_reason_says_so(self):
        assert group_admission_skip_sentence(None) == "no reason given"

    def test_empty_reason_says_so_like_none(self):
        assert group_admission_skip_sentence("") == "no reason given"
