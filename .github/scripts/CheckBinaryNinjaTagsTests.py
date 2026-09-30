#!/usr/bin/env python3

import tempfile
from pathlib import Path
import unittest

from CheckBinaryNinjaTags import discover_releases, parse_remote_refs


class TagMonitorTests(unittest.TestCase):
    def state_directory(self, stable, dev):
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name)
        (path / "stable.txt").write_text(stable + "\n", encoding="utf-8")
        (path / "dev.txt").write_text(dev + "\n", encoding="utf-8")
        self.addCleanup(temporary.cleanup)
        return path

    def test_new_tag_is_selected_when_commit_is_unchanged(self):
        stable_sha = "1" * 40
        dev_sha = "2" * 40
        refs = parse_remote_refs(
            f"{stable_sha}\trefs/tags/stable/6.0.10601\n"
            f"{dev_sha}\trefs/tags/dev/6.1.10769\n"
            f"{dev_sha}\trefs/tags/dev/6.1.10774\n"
        )
        state = self.state_directory(
            f"stable/6.0.10601 {stable_sha}",
            f"dev/6.1.10769 {dev_sha}",
        )
        releases = discover_releases(refs, state, lambda _: False)
        self.assertEqual([release["tag"] for release in releases], ["dev/6.1.10774"])

    def test_numeric_version_order_is_used(self):
        stable_sha = "1" * 40
        old_sha = "2" * 40
        new_sha = "3" * 40
        refs = parse_remote_refs(
            f"{stable_sha}\trefs/tags/stable/6.0.10601\n"
            f"{old_sha}\trefs/tags/dev/6.1.9999\n"
            f"{new_sha}\trefs/tags/dev/6.1.10000\n"
        )
        state = self.state_directory(
            f"stable/6.0.10601 {stable_sha}",
            f"dev/6.1.9999 {old_sha}",
        )
        releases = discover_releases(refs, state, lambda _: False)
        self.assertEqual(releases[0]["version"], "6.1.10000")

    def test_annotated_tag_uses_dereferenced_commit(self):
        stable_sha = "1" * 40
        tag_object = "2" * 40
        dev_sha = "3" * 40
        refs = parse_remote_refs(
            f"{stable_sha}\trefs/tags/stable/6.0.10601\n"
            f"{tag_object}\trefs/tags/dev/6.1.10769\n"
            f"{dev_sha}\trefs/tags/dev/6.1.10769^{{}}\n"
        )
        state = self.state_directory(
            f"stable/6.0.10601 {stable_sha}",
            f"dev/6.1.10769 {dev_sha}",
        )
        self.assertEqual(refs["dev/6.1.10769"].commit, dev_sha)
        self.assertEqual(discover_releases(refs, state, lambda _: False), [])

    def test_changed_recorded_tag_is_rejected(self):
        stable_sha = "1" * 40
        dev_sha = "2" * 40
        refs = parse_remote_refs(
            f"{stable_sha}\trefs/tags/stable/6.0.10601\n"
            f"{dev_sha}\trefs/tags/dev/6.1.10769\n"
        )
        state = self.state_directory(
            f"stable/6.0.10601 {stable_sha}",
            f"dev/6.1.10769 {'3' * 40}",
        )
        with self.assertRaisesRegex(RuntimeError, "changed commit"):
            discover_releases(refs, state, lambda _: False)

    def test_existing_automation_branch_suppresses_duplicate(self):
        stable_sha = "1" * 40
        old_sha = "2" * 40
        new_sha = "3" * 40
        refs = parse_remote_refs(
            f"{stable_sha}\trefs/tags/stable/6.0.10601\n"
            f"{old_sha}\trefs/tags/dev/6.1.10769\n"
            f"{new_sha}\trefs/tags/dev/6.1.10779\n"
        )
        state = self.state_directory(
            f"stable/6.0.10601 {stable_sha}",
            f"dev/6.1.10769 {old_sha}",
        )
        releases = discover_releases(refs, state, lambda _: True)
        self.assertEqual(releases, [])


if __name__ == "__main__":
    unittest.main()
