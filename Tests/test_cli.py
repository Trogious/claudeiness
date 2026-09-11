"""Exercise real macOS detection; all Slack requests go to a local fake curl."""

import json
import os
from pathlib import Path
import plistlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "claudeiness"


class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_dir = tempfile.TemporaryDirectory(prefix="claudeiness-build-")
        cls.addClassCleanup(cls.build_dir.cleanup)
        cls.fixture = Path(cls.build_dir.name) / "fixture"
        cls.unit = Path(cls.build_dir.name) / "unit"
        for source, output in [("fixture.c", cls.fixture), ("unit.c", cls.unit)]:
            subprocess.run(
                ["clang", "-Wall", "-Wextra", "-Werror", "-O2", "-lproc",
                 str(ROOT / "Tests" / source), "-o", str(output)], check=True
            )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="claudeiness-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env.pop("SLACK_TOKEN", None)
        self.prefix = "cld-" + self.directory.name.rsplit("-", 1)[-1]

    def run_cli(self, *args, check=True, env=None):
        result = subprocess.run([str(BIN), *args], env=env or self.env,
                                capture_output=True, text=True, timeout=10)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("sysctl(", result.stderr,
                             "Process integration tests need access to the macOS process table")
        return result

    def start_fixture(self, name, subdir=""):
        path = self.directory / subdir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            shutil.copy2(self.fixture, path)
        process = subprocess.Popen([str(path)], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_process, process)
        time.sleep(0.05)
        self.assertIsNone(process.poll())
        return process

    @staticmethod
    def stop_process(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def detect(self, *names):
        args = ["--json"]
        for name in names:
            args.extend(["--process", name])
        return json.loads(self.run_cli(*args).stdout)

    def fake_slack_env(self, fail_once=False):
        fake_bin = self.directory / "bin"
        fake_bin.mkdir()
        self.status_log = self.directory / "slack.jsonl"
        curl = fake_bin / "curl"
        curl.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "path = pathlib.Path(os.environ['CLD_TEST_STATUS_LOG'])\n"
            "first = not path.exists()\n"
            "payload = json.loads(sys.argv[sys.argv.index('-d') + 1])\n"
            "with path.open('a') as out: out.write(json.dumps(payload) + '\\n')\n"
            "print(json.dumps({'ok': not (first and os.environ.get('CLD_TEST_FAIL_ONCE'))}))\n"
        )
        curl.chmod(0o755)
        env = self.env.copy()
        env.update(PATH=str(fake_bin), SLACK_TOKEN="test-token",
                   CLD_TEST_STATUS_LOG=str(self.status_log))
        if fail_once:
            env["CLD_TEST_FAIL_ONCE"] = "1"
        return env

    def statuses(self):
        if not self.status_log.exists():
            return []
        return [json.loads(line)["profile"] for line in self.status_log.read_text().splitlines()]

    def wait_for_status(self, predicate):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            statuses = self.statuses()
            if predicate(statuses):
                return statuses
            time.sleep(0.05)
        self.fail(f"Expected Slack update did not arrive: {self.statuses()}")

    def test_unit_and_plist_round_trip(self):
        result = subprocess.run([str(self.unit), "--plist"], capture_output=True, check=True)
        plist = plistlib.loads(result.stdout)
        self.assertEqual(plist["ProgramArguments"], [
            "/tmp/My & tools/claudeiness", "--watch", "--process", 'Obsidian & "Notes"',
            "--process", "claude", "--interval", "17", "--json", "--quiet"
        ])
        self.assertEqual(plist["EnvironmentVariables"]["SLACK_TOKEN"], "fake<&\"'>")

    def test_invalid_flags(self):
        for args in [("--process",), ("--process", ""), ("--process=",),
                     ("--process", "--json"), ("--process", "/tmp/app"),
                     ("--process", "app\nname"), ("--process", "x" * 256),
                     ("--proccess", "Obsidian")]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_cli(*args, check=False).returncode, 0)
        args = sum((["-p", f"app-{i}"] for i in range(17)), [])
        self.assertNotEqual(self.run_cli(*args, check=False).returncode, 0)

    def test_exact_names_duplicates_and_long_names(self):
        name = self.prefix + " An App With A Long Name"
        app = self.start_fixture(name)
        helper = self.start_fixture(name + " Helper")
        result = self.detect(name.upper(), name.lower())
        self.assertEqual(result["count"], 1)
        self.assertEqual([s["pid"] for s in result["sessions"]], [app.pid])
        self.assertNotIn(helper.pid, [s["pid"] for s in result["sessions"]])

    def test_default_claude_and_explicit_selection(self):
        claude = self.start_fixture("claude")
        version = self.start_fixture("2.3.4", ".local/share/claude/versions")
        unrelated = self.start_fixture("2.3.4", "unrelated")
        name = self.prefix + " App"
        app = self.start_fixture(name)
        default_pids = {s["pid"] for s in self.detect()["sessions"]}
        self.assertTrue({claude.pid, version.pid} <= default_pids)
        self.assertTrue({unrelated.pid, app.pid}.isdisjoint(default_pids))
        self.assertEqual({s["pid"] for s in self.detect(name)["sessions"]}, {app.pid})
        both = {s["pid"] for s in self.detect("claude", name)["sessions"]}
        self.assertTrue({claude.pid, version.pid, app.pid} <= both)

    def test_json_and_slack_escape_names(self):
        name = self.prefix + ' Notes & "Quotes"\\'
        app = self.start_fixture(name)
        env = self.fake_slack_env()
        result = self.run_cli("--json", "--process=" + name, env=env)
        session = json.loads(result.stdout)["sessions"][0]
        self.assertEqual(session["pid"], app.pid)
        self.assertEqual(session["process"], name)
        self.assertEqual(Path(session["exe"]).name, name)
        self.assertEqual(self.statuses()[0]["status_text"], name)
        self.assertEqual(self.statuses()[0]["status_emoji"], ":computer:")

    def test_watch_same_total_different_apps_and_clear(self):
        first_name, second_name = self.prefix + "-A", self.prefix + "-B"
        first = self.start_fixture(first_name)
        watcher = subprocess.Popen(
            [str(BIN), "--watch", "--quiet", "--interval", "1",
             "--process", first_name, "--process", second_name],
            env=self.fake_slack_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.addCleanup(self.stop_process, watcher)
        self.wait_for_status(lambda values: values and values[0]["status_text"] == first_name)
        watcher.send_signal(signal.SIGSTOP)
        try:
            self.stop_process(first)
            self.start_fixture(second_name)
        finally:
            watcher.send_signal(signal.SIGCONT)
        self.wait_for_status(lambda values: any(v["status_text"] == second_name for v in values))
        self.stop_process(watcher)
        self.assertEqual(self.statuses()[-1], {
            "status_text": "", "status_emoji": "", "status_expiration": 0
        })

    def test_watch_retries_failed_update(self):
        name = self.prefix + "-retry"
        self.start_fixture(name)
        watcher = subprocess.Popen(
            [str(BIN), "--watch", "--quiet", "--interval", "1", "--process", name],
            env=self.fake_slack_env(fail_once=True),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.addCleanup(self.stop_process, watcher)
        values = self.wait_for_status(lambda values: len(values) >= 2)
        self.assertEqual(values[0]["status_text"], name)
        self.assertEqual(values[0], values[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
