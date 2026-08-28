# beavertrap

Triage scanner that flags the DPRK "Contagious Interview" fake-recruiter coding-test scam. It is **not** a safety guarantee.

Fake recruiters hand a developer a "take-home coding assignment" — a GitHub repo or npm package — that runs the **BeaverTail** infostealer / **InvisibleFerret** backdoor the moment you install or open it, draining crypto wallets and credentials. beavertrap statically scans the *application source you were handed* (not just the dependency tree), **deobfuscating first** — decoding hex/base64 string tables before hunting for indicators, because current samples hex-encode their IOCs specifically to beat regex scanners and human review.

---

## ⚠️ Read this first — scope & limitations

**beavertrap is triage, not a verdict of safety. Read this before you install or run it.**

- **It detects known patterns of ONE specific campaign.** A `LOW` result means "none of my signatures matched" — **not** "this is clean." It says nothing about other malware, other campaigns, or a sample built to evade it.
- **Run untrusted repos only in a disposable, network-isolated VM — regardless of the verdict.** A `LOW` from beavertrap is not permission to run something on your real machine.
- **`npm install --ignore-scripts` defuses most install-hook payloads.** Make it your default for untrusted packages; it stops the `postinstall`-hook delivery path entirely.
- **A competent or novel sample will evade it.** The deobfuscation is *shallow*: it decodes `\xNN` / `\uNNNN` escapes and simple base64. It will **not** beat XOR-, RC4-, or AES-encrypted loaders, runtime-assembled strings, or a payload fetched only at execution time.
- **Network IOCs go stale within weeks.** IPs, domains, and malicious package names rotate constantly. Do not treat the absence of a *known* IP/package as reassurance. The durable signals are wallet-extension IDs, URL-path shapes, ports, and obfuscation patterns.
- **If a recruiter pressures you to run their code quickly — that is the red flag.** No legitimate hiring process requires you to execute an unfamiliar repo on your personal machine under time pressure.

If beavertrap returns `HIGH` or `CRITICAL` and you have **already run** the code: assume compromise. From a *different* device, move any crypto to a fresh wallet with a new seed phrase, rotate passwords, revoke API keys/tokens, and wipe/reimage the machine.

---

## Install

No package manager, no dependencies. Clone and run:

```bash
git clone https://github.com/TODO-YOUR-NAME/beavertrap.git
cd beavertrap
python3 beavertrap.py /path/to/the/cloned/repo
```

Requires **Python 3.8+** and the standard library only. There is nothing to `pip install`.

**Read the script before you trust it.** `beavertrap.py` is a single ~500-line stdlib-only file with no dependencies precisely so you *can* audit it in a few minutes — do that. A tool whose whole premise is "don't run code you haven't reviewed" does not get an exception for itself. There is deliberately **no `curl | bash` installer**: that one-liner is the exact pattern this tool exists to catch.

beavertrap performs **static analysis only** — it reads files, it never executes the target.

---

## Usage

```bash
python3 beavertrap.py /path/to/repo
python3 beavertrap.py /path/to/repo --json report.json --no-color
```

Exit codes: `0` = LOW (nothing matched), `1` = HIGH, `2` = CRITICAL. Handy in CI or a pre-clone hook.

Trimmed example, run against the bundled malicious test fixture (`tests/fixtures/malicious/`, which is inert):

```
  beavertrap  -  recruiter-scam (Contagious Interview) detector
  target: tests/fixtures/malicious
  ======================================================================
  VERDICT: CRITICAL   (signal score 351)
  Matches Contagious Interview / BeaverTail signatures. Treat as live malware. Do NOT run it.
  ======================================================================

  [SMOKING GUN] VSCODE-AUTORUN
      .vscode/tasks.json
      .vscode task set to run on folder-open. Just opening the project in VS Code
      executes it - a current Contagious Interview trick.

  [SMOKING GUN] WALLET-EXT-ID  <-- hidden; found only after de-obfuscation
      install.js:2
      Hardcodes crypto wallet browser-extension ID(s): Coinbase Wallet, MetaMask.
      Legitimate code never enumerates these - this is a wallet stealer.
      > nkbihfbeogaeaoehlefnkodbefgpgknn

  [SMOKING GUN] C2-BEAVERTAIL-PORT  <-- hidden; found only after de-obfuscation
      install.js:4
      Contacts host on :1224 with a BeaverTail-style path (/pdown, /client/,
      /uploads). This is the Python second-stage fetch.
      > http://127.0.0.1:1224/pdown

  [STRONG] NPM-INSTALL-HOOK
      package.json
      'postinstall' runs automatically on `npm install` - review before installing.
      > postinstall: node install.js

  [PRETEXT] OBFUSCATION
      install.js
      Obfuscated code in application source: long \xNN hex string runs. Take-home
      assignments have no reason to ship obfuscated JS.

  ... (report continues with WEAK signals and remediation guidance)
```

Note the `<-- hidden; found only after de-obfuscation` markers: the wallet ID and C2 URL were stored as `\xNN` hex escapes and only surfaced after decoding — the case generic regex scanners miss.

The bundled *clean* fixture (`tests/fixtures/clean/`), an ordinary Express app using `axios` and `process.env`, returns `VERDICT: LOW` (exit `0`).

---

## How it works

- **Deobfuscation-first scanning.** Before matching anything, beavertrap reconstructs hidden strings: it decodes `\xNN` / `\uNNNN` escape tables (in both element-delimited and concatenated forms, to catch IOCs split across string literals) and decodes standalone base64 blobs that resolve to printable text. It then runs its indicator matchers over that decoded view as well as the raw source.
- **Per-file correlation — the "BeaverTail shape."** Any one trait is weak on its own. beavertrap raises its strongest structural signal when a *single file* combines **obfuscation + network egress + local credential/wallet access** — the anatomy of an infostealer. Network-plus-credential access alone is flagged as an exfiltration shape.
- **IOC categories it keys on:**
  - **Wallet browser-extension IDs** — known IDs (MetaMask, Phantom, Coinbase Wallet, Trust, TronLink, …) named explicitly, plus the generic 32-char `a–p` extension-ID shape when several are enumerated together.
  - **BeaverTail C2** — the `:1224` port paired with `/pdown`, `/client/<id>`, `/uploads` style paths (the Python second-stage / InvisibleFerret fetch).
  - **npm install hooks** — `preinstall`/`install`/`postinstall`/`prepare` scripts that run automatically on `npm install`, escalated when they shell out or fetch remote code; also non-registry (`git+`/`http`/`file:`/`.tgz`) dependencies.
  - **`.vscode/tasks.json` autorun** — a task with `runOn: folderOpen`, which executes just from opening the folder in VS Code.
  - Plus Solana `id.json` keyfile theft, runtime Python second-stage fetches, AnyDesk/unattended-access persistence, committed `node_modules`, and recruiter-scam pretext language in docs (low weight — context, not proof).

Findings are tiered `SMOKING GUN` / `STRONG` / `PRETEXT` / `WEAK` and summed into a single verdict: `LOW` → `SUSPICIOUS` → `HIGH` → `CRITICAL`.

---

## Reproducing the tests

```bash
tests/run_tests.sh
```

It runs `beavertrap.py --no-color` against two committed, **inert** fixtures and asserts:

- `tests/fixtures/malicious/` → `CRITICAL` (exit code `2`). It mimics the scam with **no working payload**: a `package.json` `postinstall` hook, a `.vscode/tasks.json` set to `runOn: folderOpen`, a source file where the MetaMask/Coinbase extension IDs and a `:1224/pdown` C2 URL are stored as `\xNN` hex escapes (exercising the deobfuscation path), and a README with take-home-assignment pretext. The referenced payload only does `console.log`.
- `tests/fixtures/clean/` → `LOW` (exit code `0`). A benign Express app that legitimately uses `axios` and `process.env`, to prove those everyday patterns don't false-positive.

The script prints `PASS`/`FAIL` per case and exits non-zero if either assertion fails. The fixtures are intentional — do not gitignore them, and **never** replace them with real malware.

---

## IOC freshness

The bundled signatures in [`data/iocs.md`](data/iocs.md) are **dated** and split by durability. **Network indicators — IPs, domains, and specific malicious package names — decay within weeks** as the operators rotate infrastructure; treat them as historical, not a live blocklist. The **durable** indicators, which this tool leans on, are wallet-extension IDs, the `:1224` + `/pdown`-style URL-path patterns, ports, and the obfuscation/decoder patterns. Those change far more slowly because they are tied to how the malware works, not where it is hosted.

---

## Threat-intelligence sources

beavertrap is built entirely on **published** research into the Contagious Interview / DeceptiveDevelopment campaign and the BeaverTail / InvisibleFerret toolset. It **claims no original attribution or discovery** — it operationalizes indicators and TTPs that these teams documented:

- Palo Alto Networks **Unit 42**
- **Socket**
- **ESET**
- **Group-IB**
- **Cisco Talos**
- **Microsoft** (Threat Intelligence)
- **Datadog** Security Labs
- **Silent Push**

See [`data/iocs.md`](data/iocs.md) for the specific indicators and their citations. If you maintain research this draws on and want a citation corrected or added, please open an issue.

---

## Maintenance status

**Actively maintained.** Signatures in [`data/iocs.md`](data/iocs.md) are reviewed on a **quarterly** basis. Note that a quarterly cadence is slower than the rate at which *network* IOCs (IPs, domains, package names) decay — expect those to lag between reviews, and lean on the durable detectors (wallet IDs, URL-path shapes, ports, obfuscation patterns), which age well. Corrections and IOC updates via pull request are welcome between review cycles.

---

## Contributing / reporting false positives & negatives

Found a false positive (a benign repo flagged `HIGH`/`CRITICAL`) or a false negative (a known sample it missed)? Please open a GitHub issue with the smallest reproducing detail you can share — **inert** snippets only, never a live sample or working payload. For anything touching evasion or disclosure, read [`SECURITY.md`](SECURITY.md) first.

---

## License

[MIT](LICENSE).
