# LogGhost

LogGhost is a small Python command-line project I made to practice working with Linux authentication logs. It looks for repeated failed SSH login attempts, successful SSH logins that happen after repeated failures from the same IP, and a count of authentication events by source IP.

I kept it intentionally simple: there are no third-party packages, and the sample log is synthetic. The IP addresses in the example are reserved for documentation, so they are not real attacker addresses.

## What it reports

- **Repeated failures:** an IP is listed once it reaches the chosen failure threshold (three by default).
- **Successful login after failures:** a success is flagged if that IP had already reached the threshold earlier in the file.
- **Source counts:** the number of recognized authentication events for each IP.

This is a learning project, not a complete intrusion detection system. It reads common syslog-style `sshd` messages and does not replace careful log review or a production security tool.

## Requirements

- Python 3.10 or newer
- No external dependencies (the standard library is enough)

## Run it

From this folder, run:

```bash
python -m logghost examples/auth.log
```

Use a higher or lower failure threshold like this:

```bash
python -m logghost examples/auth.log --threshold 5
```

To analyze a real Linux authentication log, point the command at it. Depending on the distribution, it may be `/var/log/auth.log` or `/var/log/secure`:

```bash
python -m logghost /var/log/auth.log
```

You may need permission to read a system log. LogGhost only reads the file you give it and prints a report; it does not change the log or block addresses.

## Example output

With the included synthetic log, the report includes three failures from `203.0.113.45`, then flags the later successful login from that same source. The other sample IPs have fewer failures and are not reported as repeated sources.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

The tests cover parsing, ignored messages, the failure threshold, the success-after-failures rule, and source counts.

## Project layout

```text
LogGhost/
├── .gitignore
├── README.md
├── requirements.txt
├── logghost/
│   ├── __init__.py
│   ├── __main__.py
│   ├── analyzer.py
│   ├── cli.py
│   └── parser.py
├── examples/
│   └── auth.log
└── tests/
    └── test_logghost.py
```

## Upload it to GitHub

1. Create a new empty repository named **LogGhost** on GitHub.
2. Open a terminal in this `LogGhost` folder.
3. Run these commands, replacing the URL with your repository URL:

```bash
git init
git add .
git commit -m "Add LogGhost authentication log analyzer"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/LogGhost.git
git push -u origin main
```

## Possible next steps

- Add support for more authentication log formats.
- Export a JSON report for other tools to consume.
- Add date-aware filtering when logs contain rotated files or full timestamps.
