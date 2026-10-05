#!/usr/bin/env python3

import tempfile
from pathlib import Path
import unittest

from CheckBinaryNinjaTags import discover_releases, parse_remote_refs


class TagMonitorTests(unittest.TestCase):
    def state_file(self, dev):
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name)
        (path / "dev.txt").write_text(dev + "\n", encoding="utf-8")
        self.addCleanup(temporary.cleanup)
        return path / "dev.txt"

    def test_new_tag_is_selected_when_commit_is_unchanged(self):
        dev_sha = "2" * 40
        refs = parse_remote_refs(
            f"{dev_sha}\trefs/tags/dev/6.1.10769\n"
            f"{dev_sha}\trefs/tags/dev/6.1.10774\n"
        )
        state = self.state_file(f"dev/6.1.10769 {dev_sha}")
        releases = discover_releases(refs, state, lambda _: False)
        self.assertEqual([release["tag"] for release in releases], ["dev/6.1.10774"])
        self.assertEqual(releases[0]["base"], "dev")

    def test_numeric_version_order_is_used(self):
        old_sha = "2" * 40
        new_sha = "3" * 40
        refs = parse_remote_refs(
            f"{old_sha}\trefs/tags/dev/6.1.9999\n"
            f"{new_sha}\trefs/tags/dev/6.1.10000\n"
        )
        state = self.state_file(f"dev/6.1.9999 {old_sha}")
        releases = discover_releases(refs, state, lambda _: False)
        self.assertEqual(releases[0]["version"], "6.1.10000")

    def test_oldest_unseen_tag_is_selected(self):
        old_sha = "2" * 40
        first_sha = "3" * 40
        second_sha = "4" * 40
        refs = parse_remote_refs(
            f"{old_sha}\trefs/tags/dev/6.1.10769\n"
            f"{first_sha}\trefs/tags/dev/6.1.10774\n"
            f"{second_sha}\trefs/tags/dev/6.1.10779\n"
        )
        state = self.state_file(f"dev/6.1.10769 {old_sha}")
        releases = discover_releases(refs, state, lambda _: False)
        self.assertEqual(releases[0]["tag"], "dev/6.1.10774")
        self.assertEqual(releases[0]["sha"], first_sha)

    def test_stable_tags_are_ignored(self):
        stable_sha = "1" * 40
        dev_sha = "2" * 40
        refs = parse_remote_refs(
            f"{stable_sha}\trefs/tags/stable/6.0.10602\n"
            f"{dev_sha}\trefs/tags/dev/6.1.10779\n"
        )
        self.assertNotIn("stable/6.0.10602", refs)
        state = self.state_file(f"dev/6.1.10779 {dev_sha}")
        releases = discover_releases(refs, state, lambda _: False)
        self.assertEqual(releases, [])

    def test_annotated_tag_uses_dereferenced_commit(self):
        tag_object = "2" * 40
        dev_sha = "3" * 40
        refs = parse_remote_refs(
            f"{tag_object}\trefs/tags/dev/6.1.10769\n"
            f"{dev_sha}\trefs/tags/dev/6.1.10769^{{}}\n"
        )
        state = self.state_file(f"dev/6.1.10769 {dev_sha}")
        self.assertEqual(refs["dev/6.1.10769"].commit, dev_sha)
        self.assertEqual(discover_releases(refs, state, lambda _: False), [])

    def test_changed_recorded_tag_is_rejected(self):
        dev_sha = "2" * 40
        refs = parse_remote_refs(
            f"{dev_sha}\trefs/tags/dev/6.1.10769\n"
        )
        state = self.state_file(f"dev/6.1.10769 {'3' * 40}")
        with self.assertRaisesRegex(RuntimeError, "changed commit"):
            discover_releases(refs, state, lambda _: False)

    def test_existing_automation_branch_suppresses_duplicate(self):
        old_sha = "2" * 40
        new_sha = "3" * 40
        refs = parse_remote_refs(
            f"{old_sha}\trefs/tags/dev/6.1.10769\n"
            f"{new_sha}\trefs/tags/dev/6.1.10779\n"
        )
        state = self.state_file(f"dev/6.1.10769 {old_sha}")
        releases = discover_releases(refs, state, lambda _: True)
        self.assertEqual(releases, [])

    def test_unpublished_current_formula_blocks_next_tag(self):
        old_sha = "2" * 40
        new_sha = "3" * 40
        refs = parse_remote_refs(
            f"{old_sha}\trefs/tags/dev/6.1.10769\n"
            f"{new_sha}\trefs/tags/dev/6.1.10779\n"
        )
        state = self.state_file(f"dev/6.1.10769 {old_sha}")
        releases = discover_releases(refs, state, lambda _: False, lambda _: False)
        self.assertEqual(releases, [])

    def test_published_current_formula_allows_next_tag(self):
        old_sha = "2" * 40
        new_sha = "3" * 40
        refs = parse_remote_refs(
            f"{old_sha}\trefs/tags/dev/6.1.10769\n"
            f"{new_sha}\trefs/tags/dev/6.1.10779\n"
        )
        state = self.state_file(f"dev/6.1.10769 {old_sha}")
        releases = discover_releases(refs, state, lambda _: False, lambda _: True)
        self.assertEqual([release["tag"] for release in releases], ["dev/6.1.10779"])


if __name__ == "__main__":
    unittest.main()
