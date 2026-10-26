from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from universalsecure.cli import main
from universalsecure.scanner import scan_directory


class ScannerTests(unittest.TestCase):
    def test_reports_patterns_and_redacts_credential_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "app.py").write_text(
                "token = 'ghp_123456789012345678901234567890123456'\n"
                "result = eval(user_input)\n",
                encoding="utf-8",
            )

            report = scan_directory(root)
            findings = report["findings"]
            self.assertEqual(report["scanned_files"], 1)
            self.assertEqual([f["rule_id"] for f in findings], ["US001", "US002"])
            self.assertNotIn("123456789012345678901234567890123456", json.dumps(report))
            self.assertIn("redacted", findings[0]["evidence"])

    def test_skips_sensitive_and_generated_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / ".env").write_text("API_KEY='super-secret-value'\n", encoding="utf-8")
            (root / "settings.py").write_text("verify=False\n", encoding="utf-8")
            generated = root / "node_modules"
            generated.mkdir()
            (generated / "package.js").write_text(
                "eval(user_input)\n",
                encoding="utf-8",
            )

            report = scan_directory(root)
            self.assertEqual(report["scanned_files"], 1)
            self.assertEqual([f["path"] for f in report["findings"]], ["settings.py"])

    def test_rejects_non_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            file_path = Path(temporary_directory) / "file.py"
            file_path.write_text("print('ok')\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not a directory"):
                scan_directory(file_path)

    def test_does_not_follow_symlinked_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "project"
            root.mkdir()
            outside_file = base / "outside.py"
            outside_file.write_text("eval(user_input)\n", encoding="utf-8")
            (root / "linked.py").symlink_to(outside_file)

            report = scan_directory(root)
            self.assertEqual(report["scanned_files"], 0)
            self.assertEqual(report["findings"], [])

    def test_cli_json_report_and_severity_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "app.py").write_text("eval(value)\n", encoding="utf-8")
            output = root.parent / f"{root.name}-report.json"
            try:
                exit_code = main(
                    [
                        "scan",
                        str(root),
                        "--format",
                        "json",
                        "--output",
                        str(output),
                        "--fail-on",
                        "medium",
                    ]
                )
                self.assertEqual(exit_code, 1)
                self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["scanned_files"], 1)
            finally:
                output.unlink(missing_ok=True)

    def test_cli_does_not_overwrite_report_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            output = root / "review.md"
            output.write_text("keep this\n", encoding="utf-8")

            exit_code = main(
                ["scan", str(root), "--output", str(output)]
            )
            self.assertEqual(exit_code, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep this\n")


if __name__ == "__main__":
    unittest.main()
