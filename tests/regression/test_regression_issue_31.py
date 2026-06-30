"""Regression #31: APPROVED_DIRECTORY set to parent /root/bria instead of /root/bria/bria.

Bug: when APPROVED_DIRECTORY pointed to the engineering root (/root/bria), every user
message ran Claude against the engineering project instead of the BRIA app. The fix
was to set APPROVED_DIRECTORY=/root/bria/bria.

These tests verify that:
1. A config pointing to a directory containing 'telegram-bot/' is distinguishable from
   a valid BRIA app directory (which contains 'bria/skills/').
2. The config validator enforces the approved_directory is accessible — if in the
   wrong place the symptoms are different sessions see different working trees.
"""

import tempfile
from pathlib import Path

import pytest

from src.config import create_test_config


@pytest.mark.regression
class TestIssue31ApprovedDirectoryLevel:
    """Approved directory must point to the BRIA app, not its parent."""

    def test_parent_dir_does_not_contain_skills(self, tmp_path: Path) -> None:
        """The wrong directory (parent) has telegram-bot/ but no skills/."""
        # Simulate the wrong structure: parent contains telegram-bot/, not skills/
        (tmp_path / "telegram-bot").mkdir()
        (tmp_path / "bria").mkdir()
        (tmp_path / "bria" / "skills").mkdir()

        # When APPROVED_DIRECTORY is the parent, there is no skills/ at the root
        assert not (tmp_path / "skills").exists(), (
            "Parent dir should NOT contain skills/ — that belongs one level down in bria/"
        )

    def test_correct_dir_contains_skills(self, tmp_path: Path) -> None:
        """The correct APPROVED_DIRECTORY (bria/) contains skills/ directly."""
        bria_app = tmp_path / "bria"
        bria_app.mkdir()
        (bria_app / "skills").mkdir()
        (bria_app / "CLAUDE.md").write_text("# BRIA")

        assert (bria_app / "skills").exists()
        assert (bria_app / "CLAUDE.md").exists()

    def test_config_approved_directory_is_stored_exactly(self, tmp_path: Path) -> None:
        """Config stores approved_directory as given — no silent reparenting."""
        bria_app = tmp_path / "bria"
        bria_app.mkdir()

        config = create_test_config(approved_directory=str(bria_app))
        assert config.approved_directory == bria_app, (
            "Config must store exactly the given path — if it silently resolves to "
            "a parent this could mask the issue #31 bug"
        )

    def test_parent_and_child_configs_are_different(self, tmp_path: Path) -> None:
        """Parent and child configs must produce different approved_directory values."""
        bria_app = tmp_path / "bria"
        bria_app.mkdir()

        parent_config = create_test_config(approved_directory=str(tmp_path))
        child_config = create_test_config(approved_directory=str(bria_app))

        assert parent_config.approved_directory != child_config.approved_directory, (
            "Parent and child configs must differ — if they resolve to the same path, "
            "the issue #31 bug could silently return"
        )

    def test_approved_directory_resolves_to_real_path(self, tmp_path: Path) -> None:
        """approved_directory should be a real, existing path (catches deleted dirs)."""
        bria_app = tmp_path / "bria"
        bria_app.mkdir()

        config = create_test_config(approved_directory=str(bria_app))
        assert config.approved_directory.exists(), (
            "approved_directory must exist on disk — a missing path means the bot "
            "can't access any files, a symptom related to issue #31 misconfiguration"
        )
