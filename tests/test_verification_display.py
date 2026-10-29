"""What a Python surface derives from the key on disk, and what it must say.

The one rule these tests exist to hold: a surface must never be able to reach
``"match"`` by feeding the server's own answer back in, so every
case here starts from key material written to a config dir.

The sentences are shared with the TypeScript twin
(``rine-core/src/verification-display.ts``) so an operator reading two surfaces
reads one vocabulary; the assertions below pin the load-bearing phrases rather
than whole paragraphs.
"""

from __future__ import annotations

from pathlib import Path

from rine._crypto.keys import save_agent_keys
from rine.testing import WORLD
from rine.verification_display import (
    compare_verification_words_for_agent,
    verification_words_lines,
)
from rine.verification_words import verification_words_for_key

AGENT_ID = "11111111-2222-3333-4444-555555555555"
OTHER_ID = "99999999-9999-9999-9999-999999999999"
OTHER_WORDS = "abandon ability able about above"


def _config_dir_with_keys(tmp_path, agent_id: str = AGENT_ID) -> tuple[str, str]:
    """A config dir holding one agent's keys, and the words they derive."""
    config_dir = str(tmp_path)
    keys = WORLD.keys(agent_id)
    save_agent_keys(config_dir, agent_id, keys)
    return config_dir, verification_words_for_key(keys.signing.public_key)


def test_compare_for_agent_when_server_asserts_the_stored_key_then_matches(tmp_path):
    config_dir, words = _config_dir_with_keys(tmp_path)
    result = compare_verification_words_for_agent(config_dir, AGENT_ID, words)
    assert result.status == "match"
    assert result.computed == words
    assert result.asserted == words
    assert result.match is True


def test_compare_for_agent_when_server_asserts_other_words_then_mismatches(tmp_path):
    config_dir, words = _config_dir_with_keys(tmp_path)
    result = compare_verification_words_for_agent(config_dir, AGENT_ID, OTHER_WORDS)
    assert result.status == "mismatch"
    assert result.computed == words
    assert result.asserted == OTHER_WORDS
    assert result.match is False


def test_compare_for_agent_when_no_key_on_disk_then_not_computed(tmp_path):
    config_dir, _ = _config_dir_with_keys(tmp_path)
    result = compare_verification_words_for_agent(config_dir, OTHER_ID, OTHER_WORDS)
    assert result.status == "not-computed"
    assert result.computed is None
    assert result.asserted == OTHER_WORDS


def test_compare_for_agent_when_key_is_corrupt_then_not_computed(tmp_path):
    config_dir, _ = _config_dir_with_keys(tmp_path)
    (tmp_path / "keys" / AGENT_ID / "signing.key").write_text("not-a-key")
    result = compare_verification_words_for_agent(config_dir, AGENT_ID, OTHER_WORDS)
    assert result.status == "not-computed"


def test_compare_for_agent_when_server_names_no_words_then_not_asserted(tmp_path):
    config_dir, words = _config_dir_with_keys(tmp_path)
    result = compare_verification_words_for_agent(config_dir, AGENT_ID, None)
    assert result.status == "not-asserted"
    assert result.computed == words


def test_lines_when_matching_then_one_line(tmp_path):
    config_dir, words = _config_dir_with_keys(tmp_path)
    lines = verification_words_lines(
        compare_verification_words_for_agent(config_dir, AGENT_ID, words)
    )
    assert lines == [f"Verification words: {words}"]


def test_lines_when_mismatching_then_both_values_render(tmp_path):
    config_dir, words = _config_dir_with_keys(tmp_path)
    lines = verification_words_lines(
        compare_verification_words_for_agent(config_dir, AGENT_ID, OTHER_WORDS)
    )
    joined = "\n".join(lines)
    assert words in joined
    assert OTHER_WORDS in joined
    assert "this client" in lines[0]
    assert "server" in lines[1]


def test_lines_when_mismatching_then_it_is_not_alarming_and_names_a_remedy(tmp_path):
    config_dir, _ = _config_dir_with_keys(tmp_path)
    joined = " ".join(
        verification_words_lines(
            compare_verification_words_for_agent(config_dir, AGENT_ID, OTHER_WORDS)
        )
    )
    assert "Messages still send and arrive" in joined
    assert "RINE_CONFIG_DIR" in joined


def test_lines_when_not_computed_then_the_server_string_is_labelled_as_such(tmp_path):
    config_dir, _ = _config_dir_with_keys(tmp_path)
    lines = verification_words_lines(
        compare_verification_words_for_agent(config_dir, OTHER_ID, OTHER_WORDS)
    )
    assert lines[0] == f"Verification words (server): {OTHER_WORDS}"
    assert "Not recomputed here" in " ".join(lines)


def test_lines_when_nothing_is_known_then_nothing_is_printed(tmp_path):
    config_dir, _ = _config_dir_with_keys(tmp_path)
    assert (
        verification_words_lines(compare_verification_words_for_agent(config_dir, OTHER_ID, None))
        == []
    )


def test_lines_when_the_server_names_none_then_the_computed_words_show(tmp_path):
    config_dir, words = _config_dir_with_keys(tmp_path)
    lines = verification_words_lines(
        compare_verification_words_for_agent(config_dir, AGENT_ID, None)
    )
    assert lines[0] == f"Verification words: {words}"
    assert "nothing to compare" in " ".join(lines)


def test_lines_when_a_label_is_given_then_it_is_used(tmp_path):
    config_dir, words = _config_dir_with_keys(tmp_path)
    lines = verification_words_lines(
        compare_verification_words_for_agent(config_dir, AGENT_ID, words),
        label="Verify words",
    )
    assert lines == [f"Verify words: {words}"]


def test_lines_when_read_beside_the_typescript_twin_then_the_sentences_agree(tmp_path):
    """One vocabulary across the two client stacks, pinned rather than assumed.

    A surface-by-surface rewording is how ten copies of an explanation start.
    """
    config_dir, _ = _config_dir_with_keys(tmp_path)
    ts_source = Path(__file__).parents[2] / "rine-core" / "src" / "verification-display.ts"
    if not ts_source.is_file():  # pragma: no cover - rine-core not checked out
        return
    ts_text = ts_source.read_text()
    for line in verification_words_lines(
        compare_verification_words_for_agent(config_dir, AGENT_ID, OTHER_WORDS)
    )[2:]:
        assert line in ts_text, line
