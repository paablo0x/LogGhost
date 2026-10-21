import unittest

from logghost.analyzer import analyze
from logghost.parser import parse_line, parse_lines


class ParserTests(unittest.TestCase):
    def test_failed_password_and_invalid_user(self):
        event = parse_line("Oct 21 10:15:01 host sshd[123]: Failed password for invalid user guest from 203.0.113.42 port 22 ssh2", 7)
        self.assertEqual((event.source_ip, event.outcome, event.username, event.line_number),
                         ("203.0.113.42", "failure", "guest", 7))

    def test_success(self):
        event = parse_line("Oct 21 10:16:01 host sshd[123]: Accepted publickey for sam from 198.51.100.9 port 22 ssh2")
        self.assertEqual((event.outcome, event.username), ("success", "sam"))

    def test_unrecognized_line_is_ignored(self):
        self.assertIsNone(parse_line("Oct 21 10:16:01 host cron[1]: job started"))


class AnalyzerTests(unittest.TestCase):
    def test_repeated_failures_then_success_and_source_counts(self):
        events = parse_lines([
            "Oct 21 10:00:00 host sshd[1]: Failed password for root from 203.0.113.42 port 22 ssh2\n",
            "Oct 21 10:01:00 host sshd[2]: Failed password for root from 203.0.113.42 port 22 ssh2\n",
            "Oct 21 10:02:00 host sshd[3]: Failed password for root from 203.0.113.42 port 22 ssh2\n",
            "Oct 21 10:03:00 host sshd[4]: Accepted password for root from 203.0.113.42 port 22 ssh2\n",
            "Oct 21 10:04:00 host sshd[5]: Accepted publickey for sam from 198.51.100.9 port 22 ssh2\n",
        ])
        report = analyze(events, threshold=3)
        self.assertEqual(report["source_counts"], {"203.0.113.42": 4, "198.51.100.9": 1})
        self.assertEqual(report["repeated_failure_sources"], {"203.0.113.42": 3})
        self.assertEqual(len(report["suspicious_successes"]), 1)
        self.assertEqual(report["suspicious_successes"][0].line_number, 4)

    def test_success_before_threshold_is_not_flagged(self):
        events = parse_lines([
            "Oct 21 10:00:00 host sshd[1]: Failed password for root from 203.0.113.42 port 22 ssh2",
            "Oct 21 10:01:00 host sshd[2]: Accepted password for root from 203.0.113.42 port 22 ssh2",
            "Oct 21 10:02:00 host sshd[3]: Failed password for root from 203.0.113.42 port 22 ssh2",
        ])
        self.assertEqual(analyze(events, 3)["suspicious_successes"], [])

    def test_threshold_must_be_positive(self):
        with self.assertRaises(ValueError):
            analyze([], 0)


if __name__ == "__main__":
    unittest.main()
