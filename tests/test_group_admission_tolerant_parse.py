"""A group admission report parses a skip token this client predates.

``org_rule`` is the first token a rule refusal emits. A strict ``Literal`` made a plural invite
raise a parse error the moment the server refused one agent for a reason the client did not
know, after the other invitations were already minted. The report must parse, keep the raw
string, and render without raising.
"""

from __future__ import annotations

import pytest

from rine.admission_words import describe_admission_entry
from rine.group_admission import GroupAdmissionReport

AGENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER = "99999999-bbbb-cccc-dddd-eeeeeeeeeeee"


def _report(reason: str) -> GroupAdmissionReport:
    return GroupAdmissionReport.model_validate(
        {
            "invited": 1,
            "skipped": 1,
            "entries": [
                {"agent_id": OTHER, "status": "invited"},
                {"agent_id": AGENT, "status": "skipped", "reason": reason},
            ],
        }
    )


def test_group_admission_report_when_the_reason_is_org_rule_then_it_parses() -> None:
    report = _report("org_rule")

    assert report.entries[1].reason == "org_rule"
    assert report.entries[0].status == "invited"


@pytest.mark.parametrize("token", ["some_future_reason", "ORG_RULE_V2", ""])
def test_group_admission_report_when_the_reason_is_unknown_then_it_parses_and_keeps_the_string(
    token: str,
) -> None:
    assert _report(token).entries[1].reason == token


def test_describe_admission_entry_when_the_reason_is_org_rule_then_it_says_the_rule_refused() -> (
    None
):
    line = describe_admission_entry(_report("org_rule").entries[1])

    assert line.startswith(f"{AGENT}: refused by an organisation's group rule")


def test_describe_admission_entry_when_the_reason_is_unknown_then_it_renders_without_raising() -> (
    None
):
    line = describe_admission_entry(_report("some_future_reason").entries[1])

    assert line == f"{AGENT}: reason not recognised by this client: some_future_reason"
