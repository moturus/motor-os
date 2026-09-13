#!/usr/bin/env python3
"""Observe initial project + std loading in Helix's existing LSP log."""
import json
from pathlib import Path
import re
import sys
import unittest


def ready(lines):
    active = set()
    loaded = scanned = checked = False
    for line in lines:
        # Only INFO transport records carry wire JSON. ERROR records can
        # repeat the same arrow with a human-readable ServerError message.
        _, separator, payload = line.partition(
            "helix_lsp::transport [INFO] rust-analyzer <- ")
        if not separator:
            continue
        try:
            message = json.loads(payload)
        except json.JSONDecodeError:
            # The editor may still be appending the final line during cat.
            return False
        if message.get("method") != "$/progress":
            continue
        params = message["params"]
        token, value = params["token"], params["value"]
        kind = value["kind"]
        if kind == "begin":
            active.add(token)
        elif kind == "end":
            active.discard(token)
        if token == "rustAnalyzer/Roots Scanned":
            if kind == "begin":
                loaded = scanned = False
            count = re.match(r"^(\d+)/(\d+)(?::|$)", value.get("message", ""))
            if count:
                done, total = map(int, count.groups())
                loaded = done == total and total >= 2
            if kind == "end":
                scanned = loaded
        if token.startswith("rust-analyzer/flycheck/") and kind == "end":
            checked = True
    return scanned and checked and not active


def progress(token, kind, **fields):
    return "helix_lsp::transport [INFO] rust-analyzer <- " + json.dumps({
        "method": "$/progress", "params": {
            "token": token, "value": {"kind": kind, **fields}}})


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.roots = "rustAnalyzer/Roots Scanned"
        self.check = progress("rust-analyzer/flycheck/0", "end")
        self.scan = [progress(self.roots, "begin"),
                     progress(self.roots, "report", message="2/2"),
                     progress(self.roots, "end")]

    def test_compiler_check_does_not_imply_loaded_sources(self):
        self.assertFalse(ready([self.check]))
        self.assertFalse(ready(self.scan))
        self.assertTrue(ready([self.check] + self.scan))

    def test_initial_project_only_scan_is_not_ready(self):
        self.assertFalse(ready([self.check, progress(self.roots, "begin"),
                                progress(self.roots, "report", message="1/1"),
                                progress(self.roots, "end")]))

    def test_reload_and_indexing_must_finish(self):
        lines = [self.check] + self.scan
        lines += [progress("rustAnalyzer/cachePriming", "begin")]
        self.assertFalse(ready(lines))
        lines += [progress(self.roots, "begin")]
        lines += [progress("rustAnalyzer/cachePriming", "end")]
        self.assertFalse(ready(lines))
        self.assertTrue(ready(lines + self.scan))

    def test_incomplete_log_is_not_ready(self):
        partial = 'helix_lsp::transport [INFO] rust-analyzer <- {'
        self.assertFalse(ready([self.check] + self.scan + [partial]))

    def test_formatted_content_modified_error_is_not_a_wire_message(self):
        # Editing during initialization cancels an obsolete signature-help
        # request. Helix logs its JSON reply and a separate readable error.
        error = ('helix_lsp::transport [ERROR] rust-analyzer <- '
                 'ServerError(-32801): content modified')
        self.assertTrue(ready([error, self.check] + self.scan))
        self.assertFalse(ready([error, self.check]))


if __name__ == "__main__":
    if len(sys.argv) == 2:
        sys.exit(0 if ready(Path(sys.argv[1]).read_text().splitlines()) else 1)
    unittest.main()
