"""Run the tests with the standard library and optionally write a JUnit XML report.

    python tests/run_tests.py [--junit PATH]
"""

import argparse
import os
import sys
import time
import unittest
from xml.etree import ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(ROOT, "vendor"))
sys.path.insert(0, ROOT)


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []
        self._started = {}

    def startTest(self, test):
        self._started[test.id()] = time.monotonic()
        super().startTest(test)

    def _record(self, test, outcome, detail=""):
        elapsed = time.monotonic() - self._started.get(test.id(), time.monotonic())
        self.records.append((test.id(), outcome, detail, elapsed))

    def addSuccess(self, test):
        super().addSuccess(test)
        self._record(test, "passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._record(test, "failure", self._exc_info_to_string(err, test))

    def addError(self, test, err):
        super().addError(test, err)
        self._record(test, "error", self._exc_info_to_string(err, test))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._record(test, "skipped", reason)


def write_junit(path, records):
    suite = ET.Element(
        "testsuite", name="familyhub", tests=str(len(records)),
        failures=str(sum(r[1] == "failure" for r in records)),
        errors=str(sum(r[1] == "error" for r in records)),
        skipped=str(sum(r[1] == "skipped" for r in records)),
    )
    for test_id, outcome, detail, elapsed in records:
        module_class, _, name = test_id.rpartition(".")
        case = ET.SubElement(suite, "testcase", classname=module_class, name=name, time=f"{elapsed:.3f}")
        if outcome in ("failure", "error", "skipped"):
            ET.SubElement(case, outcome, message=detail.splitlines()[-1] if detail else "").text = detail
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--junit", help="where to write a JUnit XML report")
    args = parser.parse_args()
    tests = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py", top_level_dir=ROOT)
    runner = unittest.TextTestRunner(resultclass=RecordingResult, verbosity=2)
    result = runner.run(tests)
    if args.junit:
        write_junit(args.junit, result.records)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
