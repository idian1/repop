# Security Policy

## What beavertrap is — and is not

beavertrap is a **triage aid**, not a security control. It is **not antivirus**, not an EDR, and **not a substitute for running untrusted code in a disposable, network-isolated VM**. A `LOW` verdict means "no signature in this tool matched" — it is never proof that a repo is safe. Treat every unfamiliar take-home assignment or unsolicited package as hostile until you have inspected it in an isolated environment, regardless of what beavertrap reports.

## Reporting false positives and false negatives

Detection-quality issues are **normal bug reports** — please use the public GitHub issue tracker:

- **False positive** — a benign project flagged `HIGH` or `CRITICAL`. Include the smallest **inert** snippet or file structure that triggers it and the verdict you got.
- **False negative** — a *publicly documented* sample or pattern beavertrap misses. Describe the technique and link the public write-up.

**Never attach, paste, or link a live malware sample or a working payload.** Reduce it to an inert description or a harmless string that reproduces the matching behavior. Maintainers will not download live samples from issues.

## Reporting an evasion technique (responsible disclosure)

If you find a way to make a real malicious repo slip past beavertrap:

- **Already-public techniques** (described in existing threat-intel reporting, conference talks, or blog posts): open a normal GitHub issue and cite the source. Discussing already-published evasion in the open helps everyone.
- **Novel, not-yet-public techniques** — anything that would hand real attackers a working bypass before a fix exists: **do not open a public issue.** Contact the maintainer privately first at **ahmad.suddle@gmail.com**. Please allow a reasonable window to ship a signature update before public disclosure.

There is no bug-bounty program. This is a best-effort open-source project — see the maintenance status in the [README](README.md#maintenance-status).

## Scope

In scope: the detection logic in `beavertrap.py`, the signatures in `data/iocs.md`, and the test fixtures. Out of scope: the malware itself (report that to the vendors and platforms hosting it), and general Python/OS vulnerabilities unrelated to this tool.
