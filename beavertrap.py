#!/usr/bin/env python3
"""
beavertrap - a detector tuned for ONE thing: the fake-recruiter coding-test
scam (the campaign the security world tracks as "Contagious Interview" /
"DeceptiveDevelopment", run by a DPRK-linked crew, delivering the BeaverTail
stealer + InvisibleFerret Python backdoor).

Why this exists when Socket / npm audit already do supply-chain scanning:
those tools focus on the npm REGISTRY and your DEPENDENCY tree. The version of
this attack aimed at a job-seeker is a GitHub repo (or zip) handed to you as a
"take-home assignment", where the payload is planted in the APPLICATION SOURCE
you'd run while "just getting it working" - a place dependency scanners don't
weight. And current samples hex-encode the payload specifically to beat regex
scanners and human review.

So this tool does two things generic scanners don't:
  1. DEOBFUSCATES FIRST. It decodes \\xNN / \\uNNNN string tables and base64
     blobs, then hunts for indicators in the decoded text - catching the
     wallet-extension IDs / C2 URLs the attacker deliberately hid.
  2. CORRELATES per-file. Obfuscation alone is boring. Obfuscation + network
     egress + wallet/keychain access in the SAME file is the BeaverTail shape.

It outputs a single tuned verdict: how strongly this repo matches the
recruiter-scam pattern, and WHICH family signals fired.

NOT A SAFETY CERTIFICATE. A low score means "I didn't match my signatures",
not "this is clean". Run untrusted code only in a throwaway VM. `npm install
--ignore-scripts` first. If a recruiter rushes you to run their code, that IS
the scam.

Usage:
    python3 beavertrap.py /path/to/cloned/repo
    python3 beavertrap.py /path/to/repo --json report.json --no-color

Exit codes: 0 clean-ish, 1 suspicious (HIGH), 2 near-certain (CRITICAL / smoking gun).
Stdlib only. Python 3.8+.  All static analysis - it never executes the target.
"""

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict

# =============================================================================
# Family knowledge - the fingerprints that make this "tuned" rather than generic
# =============================================================================

# Canonical Chrome extension IDs BeaverTail enumerates. The list the malware
# uses grows over time (9 -> 13 -> 22 -> 43 wallets), so we ALSO match the
# generic shape of a Chrome extension ID below - but naming the known ones lets
# us say "this targets MetaMask" out loud.
KNOWN_WALLET_EXT_IDS = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "fhbohimaelbohpjbbldcngcnapndodjp": "BNB Chain Wallet",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
    "bfnaelmomeimhlpmgjnjophhpkoljnlb": "Phantom",
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
    "aeachknmefphepccionboohckonoeemg": "Coin98",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
    "nphplpgoakhhjchkkhmiggakijnkhfnd": "Ton Wallet",
    "fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin Wallet",
    "hpglfhgfnhbgpjdenjgmdgoeiappafln": "Guarda / Argent",
    "afbcbjpbpfadlkmhmclhkeeodmamcflc": "Math Wallet",
}

# A Chrome extension ID is exactly 32 chars, lowercase a-p only. Enumerating
# several of these together is something legit app code essentially never does.
RX_EXT_ID = re.compile(r"\b[a-p]{32}\b")

# BeaverTail's second-stage machinery. It fetches Python from <c2>:1224/pdown
# and InvisibleFerret from <c2>:1224/client/<id>. Port 1224 + these paths are
# a very distinctive tell.
RX_C2_PORT = re.compile(r":1224\b")
RX_C2_PATHS = re.compile(r"/(pdown|client/\d|uploads?/|keys?/|adc|payload)", re.I)

# Solana keypair file - direct private-key theft.
RX_SOLANA_KEY = re.compile(r"\bid\.json\b")
RX_SOLANA_DIR = re.compile(r"\.config[\\/]solana", re.I)

# obfuscator.io signature: _0xABCD hex-named identifiers, huge string arrays.
RX_OBF_HEXNAME = re.compile(r"_0x[0-9a-f]{4,6}\b")
RX_HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
RX_UNICODE_RUN = re.compile(r"(?:\\u[0-9a-fA-F]{4}){6,}")

# network egress markers
RX_NETWORK = re.compile(
    r"\b(fetch|axios|XMLHttpRequest|https?\.(get|request|post)|require\(['\"]https?['\"]\)|"
    r"WebSocket|net\.connect|dgram)\b|curl\s|wget\s", re.I)
RX_HTTP_POST = re.compile(r"method\s*[:=]\s*['\"]POST['\"]|\.post\s*\(", re.I)

# local sensitive-data access markers
RX_HOME = re.compile(r"os\.homedir\(\)|process\.env\.(HOME|USERPROFILE|APPDATA|LOCALAPPDATA)|"
                     r"Application Support|AppData|Library[\\/]Keychains", re.I)
RX_CREDSTORE = re.compile(
    r"(Login Data|Local State|Cookies|leveldb|\.ldb\b|Local Storage|login\.keychain|"
    r"\.ssh[\\/]|id_rsa|id_ed25519)", re.I)
RX_WALLET_KW = re.compile(r"\b(metamask|exodus|electrum|phantom|keplr|wallet\.dat|"
                          r"keystore|mnemonic|seed phrase|passphrase|private\s*key)\b", re.I)
RX_FS_SWEEP = re.compile(r"\b(readdir|walk|glob|scandir)\b[\s\S]{0,80}"
                         r"(wallet|metamask|bitcoin|backup|phrase|keystore)", re.I)

# second-stage / persistence
RX_PY_FETCH = re.compile(r"(curl|wget|fetch|download)[^\n]{0,80}(python|\.py\b|pdown)", re.I)
RX_ANYDESK = re.compile(r"anydesk|--unattended|unattended[_-]?access", re.I)

# npm install hooks (payload runs on `npm install`)
DANGEROUS_LIFECYCLE = {"preinstall", "install", "postinstall",
                       "prepare", "prepublish", "prepublishOnly"}

# Social-pretext markers in READMEs / docs. Low weight alone, but they confirm
# the delivery story: "run this to complete the assessment".
RX_PRETEXT = re.compile(
    r"\b(take[- ]?home|coding (test|challenge|assessment)|technical (test|assessment)|"
    r"complete the (task|assignment)|record (a|your) (video|loom)|"
    r"run npm (install|start)[\s\S]{0,40}(and|then)|before (the|our) (call|interview))\b", re.I)

TEXT_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".json",
             ".sh", ".bash", ".ps1", ".bat", ".md", ".txt", ".yml", ".yaml",
             ".html", ".vue", ".svelte", ".env"}
SKIP_DIRS = {".git"}
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_DECODE_BYTES = 300 * 1024
SNIPPET_LEN = 150

# =============================================================================
# Signal + verdict model.  Each signal carries a weight; smoking guns are huge.
# =============================================================================

TIER_SMOKING = "SMOKING GUN"   # any one ~= confirmed
TIER_STRONG = "STRONG"
TIER_PRETEXT = "PRETEXT"
TIER_WEAK = "WEAK"

TIER_WEIGHT = {TIER_SMOKING: 100, TIER_STRONG: 35, TIER_PRETEXT: 12, TIER_WEAK: 4}

@dataclass
class Signal:
    tier: str
    code: str
    path: str
    line: int
    message: str
    snippet: str = ""
    decoded: bool = False   # was this found only after deobfuscation?

@dataclass
class Report:
    root: str
    signals: list = field(default_factory=list)

    def add(self, s: Signal):
        self.signals.append(s)

    def score(self):
        return sum(TIER_WEIGHT.get(s.tier, 0) for s in self.signals)

    def verdict(self):
        has_smoking = any(s.tier == TIER_SMOKING for s in self.signals)
        sc = self.score()
        if has_smoking or sc >= 100:
            return ("CRITICAL",
                    "Matches Contagious Interview / BeaverTail signatures. "
                    "Treat as live malware. Do NOT run it.")
        if sc >= 35:
            return ("HIGH",
                    "Strongly consistent with the fake-recruiter scam pattern. "
                    "Do not run outside a disposable, network-isolated VM.")
        if sc >= 12:
            return ("SUSPICIOUS",
                    "Some pretext/obfuscation signals. Inspect the flagged files "
                    "manually before running anything.")
        return ("LOW",
                "No family signatures matched. This is NOT a clean bill of health - "
                "see the note below.")

# =============================================================================
# Deobfuscation - decode what the attacker hid, so we can scan it
# =============================================================================

RX_STRING_LIT = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|`((?:[^`\\]|\\.)*)`")
RX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u\{?([0-9a-fA-F]{1,6})\}?")
RX_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

def _decode_escapes(s):
    def repl(m):
        code = m.group(1) or m.group(2)
        try:
            return chr(int(code, 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return RX_ESCAPE.sub(repl, s)

def build_decoded_view(text):
    """Reconstruct hidden strings so IOCs become greppable. Returns decoded text.

    We emit TWO joinings of the decoded string literals and scan both:
      - newline-DELIMITED: preserves each literal's boundaries, so a whole
        extension ID / C2 URL stored as one hex-encoded array element matches
        cleanly (this is how obfuscator.io string tables actually look).
      - CONCATENATED: catches an IOC deliberately SPLIT across several literals
        ("nkbi"+"hfbe"+...), which the delimited view would break apart.
    Scanning the union covers both evasion styles."""
    out = []
    pieces = []
    for m in RX_STRING_LIT.finditer(text):
        lit = m.group(1) or m.group(2) or m.group(3) or ""
        pieces.append(_decode_escapes(lit) if ("\\x" in lit or "\\u" in lit) else lit)
        if sum(len(x) for x in pieces) > MAX_DECODE_BYTES:
            break
    out.append("\n".join(pieces))   # delimited
    out.append("".join(pieces))     # concatenated

    # 2) Standalone base64 blobs that decode to mostly-printable text.
    total = 0
    for m in RX_B64_BLOB.finditer(text):
        blob = m.group(0)
        if len(blob) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            continue
        printable = sum(1 for b in raw if 9 <= b <= 13 or 32 <= b <= 126)
        if raw and printable / len(raw) > 0.85:
            dec = raw.decode("latin-1", "replace")
            out.append(dec)
            total += len(dec)
            if total > MAX_DECODE_BYTES:
                break

    return "\n".join(out)[:MAX_DECODE_BYTES]

# =============================================================================
# Per-file analysis
# =============================================================================

def clean_snippet(s):
    s = s.strip().replace("\t", " ")
    return s[:SNIPPET_LEN] + (" ...[truncated]" if len(s) > SNIPPET_LEN else "")

def _find_line(text, needle):
    idx = text.find(needle)
    if idx < 0:
        return 0, ""
    line_no = text.count("\n", 0, idx) + 1
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    end = len(text) if end < 0 else end
    return line_no, clean_snippet(text[start:end])

def scan_wallet_ids(text, rel, report, decoded):
    # Known IDs: exact 32-char substrings, matched without word boundaries so
    # they still fire even when concatenation glues them to neighbouring tokens.
    known = {i: name for i, name in KNOWN_WALLET_EXT_IDS.items() if i in text}
    # Generic shape: boundaried, to avoid sliding-window false positives.
    ids = set(m.group(0) for m in RX_EXT_ID.finditer(text)) | set(known)
    if not ids:
        return
    # A single random 32-char a-p token is not damning. Several, or any known
    # wallet ID, is the strongest indicator in the whole toolkit.
    if known:
        names = ", ".join(sorted(set(known.values())))
        ln, snip = _find_line(text, next(iter(known)))
        report.add(Signal(TIER_SMOKING, "WALLET-EXT-ID", rel, ln,
                          f"Hardcodes crypto wallet browser-extension ID(s): {names}. "
                          f"Legitimate code never enumerates these - this is a wallet stealer.",
                          snip, decoded))
    elif len(ids) >= 3:
        ln, snip = _find_line(text, sorted(ids)[0])
        report.add(Signal(TIER_STRONG, "WALLET-EXT-ID-SHAPE", rel, ln,
                          f"Enumerates {len(ids)} Chrome-extension-ID-shaped tokens "
                          f"(32-char a-p). Consistent with a wallet-extension stealer.",
                          snip, decoded))

def scan_c2(text, rel, report, decoded):
    if RX_C2_PORT.search(text) and RX_C2_PATHS.search(text):
        ln, snip = _find_line(text, ":1224")
        report.add(Signal(TIER_SMOKING, "C2-BEAVERTAIL-PORT", rel, ln,
                          "Contacts host on :1224 with a BeaverTail-style path "
                          "(/pdown, /client/, /uploads). This is the Python second-stage fetch.",
                          snip, decoded))
    elif RX_C2_PATHS.search(text) and RX_NETWORK.search(text):
        m = RX_C2_PATHS.search(text)
        ln, snip = _find_line(text, m.group(0))
        report.add(Signal(TIER_STRONG, "C2-PATH", rel, ln,
                          "Network call to a BeaverTail-style endpoint path.", snip, decoded))

def scan_solana(text, rel, report, decoded):
    if RX_SOLANA_KEY.search(text) and (RX_SOLANA_DIR.search(text) or RX_WALLET_KW.search(text)
                                       or RX_NETWORK.search(text)):
        ln, snip = _find_line(text, "id.json")
        report.add(Signal(TIER_STRONG, "SOLANA-KEYFILE", rel, ln,
                          "Reads Solana's id.json (raw private key) near wallet/network code.",
                          snip, decoded))

def scan_second_stage(text, rel, report, decoded):
    if RX_PY_FETCH.search(text):
        m = RX_PY_FETCH.search(text)
        ln, snip = _find_line(text, m.group(0))
        report.add(Signal(TIER_STRONG, "PY-SECOND-STAGE", rel, ln,
                          "Downloads/executes Python at runtime - InvisibleFerret delivery pattern.",
                          snip, decoded))
    if RX_ANYDESK.search(text):
        m = RX_ANYDESK.search(text)
        ln, snip = _find_line(text, m.group(0))
        report.add(Signal(TIER_STRONG, "ANYDESK-UNATTENDED", rel, ln,
                          "References AnyDesk / unattended access - remote-control persistence.",
                          snip, decoded))

def obfuscation_signals(text):
    hits = []
    if len(RX_OBF_HEXNAME.findall(text)) >= 5:
        hits.append("_0x hex-named identifiers (javascript-obfuscator)")
    if RX_HEX_RUN.search(text):
        hits.append("long \\xNN hex string runs")
    if RX_UNICODE_RUN.search(text):
        hits.append("long \\uNNNN unicode runs")
    return hits

def scan_correlation(text, rel, report, ext):
    """The BeaverTail shape: obfuscation + network + local-sensitive-access in
    ONE file. Any one alone is weak; together they are the malware's anatomy."""
    if ext not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"}:
        return
    obf = bool(obfuscation_signals(text)) or (
        max((len(l) for l in text.splitlines()), default=0) > 1000)
    net = bool(RX_NETWORK.search(text)) or bool(RX_HTTP_POST.search(text))
    sens = bool(RX_HOME.search(text)) or bool(RX_CREDSTORE.search(text)) or bool(RX_WALLET_KW.search(text))
    score = sum([obf, net, sens])
    if score == 3:
        report.add(Signal(TIER_SMOKING, "BEAVERTAIL-SHAPE", rel, 0,
                          "Single file combines obfuscation + network egress + local "
                          "credential/wallet access. This is the BeaverTail infostealer anatomy.",
                          ""))
    elif net and sens:
        report.add(Signal(TIER_STRONG, "EXFIL-SHAPE", rel, 0,
                          "File reads local credentials/wallet data AND makes network calls - "
                          "the exfiltration pattern.", ""))
    elif obf and (net or sens):
        report.add(Signal(TIER_PRETEXT, "OBFUSCATED-ACTIVE", rel, 0,
                          "Obfuscated code that also touches the network or local files - "
                          "why is app-source code hidden?", ""))

def analyze_file(path, rel, report):
    ext = os.path.splitext(path)[1].lower()
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            report.add(Signal(TIER_WEAK, "OVERSIZE", rel, 0,
                              "File too large to scan - inspect manually.", ""))
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return

    name = os.path.basename(path)

    # package.json lifecycle hooks (payload runs on `npm install`)
    if name == "package.json":
        _scan_package_json(text, rel, report)

    # .vscode/tasks.json autorun-on-open (newest delivery trick)
    if name == "tasks.json" and ".vscode" in rel.replace("\\", "/"):
        _scan_vscode_task(text, rel, report)

    # README / doc pretext
    if ext in {".md", ".txt"} and RX_PRETEXT.search(text):
        m = RX_PRETEXT.search(text)
        ln, snip = _find_line(text, m.group(0))
        report.add(Signal(TIER_WEAK, "PRETEXT-DOC", rel, ln,
                          "Instructions read like the recruiter-scam delivery "
                          "(take-home / run-and-record). Context, not proof.", snip))

    # Run IOC detectors on RAW text ...
    for fn in (scan_wallet_ids, scan_c2, scan_solana, scan_second_stage):
        fn(text, rel, report, decoded=False)
    scan_correlation(text, rel, report, ext)

    # ... then on the DEOBFUSCATED view, to catch what they hid.
    decoded = build_decoded_view(text)
    if decoded and decoded.strip():
        for fn in (scan_wallet_ids, scan_c2, scan_solana, scan_second_stage):
            fn(decoded, rel, report, decoded=True)

    # Note obfuscation itself once, so the user knows why decoding mattered.
    obf = obfuscation_signals(text)
    if obf and ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        report.add(Signal(TIER_PRETEXT, "OBFUSCATION", rel, 0,
                          "Obfuscated code in application source: " + "; ".join(obf) +
                          ". Take-home assignments have no reason to ship obfuscated JS.", ""))

def _scan_package_json(text, rel, report):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for hook, cmd in scripts.items():
            if hook in DANGEROUS_LIFECYCLE and isinstance(cmd, str):
                tier = TIER_STRONG
                if any(x in cmd.lower() for x in
                       ("curl", "wget", "node -e", "node -p", "child_process",
                        "base64", "http", ".sh", "powershell", "|")):
                    tier = TIER_SMOKING
                report.add(Signal(tier, "NPM-INSTALL-HOOK", rel, 0,
                                  f"'{hook}' runs automatically on `npm install`"
                                  + (" and shells out / fetches remote code." if tier == TIER_SMOKING
                                     else " - review before installing."),
                                  clean_snippet(f"{hook}: {cmd}")))
    for fld in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(fld, {})
        if isinstance(deps, dict):
            for nm, spec in deps.items():
                if isinstance(spec, str) and (spec.lower().startswith(("git+", "http", "file:"))
                                              or "github:" in spec.lower() or spec.endswith(".tgz")):
                    report.add(Signal(TIER_PRETEXT, "NONREGISTRY-DEP", rel, 0,
                                      f"Dependency '{nm}' pulls from a non-registry source "
                                      f"({spec}) - bypasses npm review.",
                                      clean_snippet(f"{nm}: {spec}")))

def _scan_vscode_task(text, rel, report):
    try:
        data = json.loads(re.sub(r"//.*", "", text))  # strip line comments (jsonc)
    except json.JSONDecodeError:
        data = None
    autorun = '"folderopen"' in text.lower() or '"runon"' in text.lower()
    if autorun:
        report.add(Signal(TIER_SMOKING, "VSCODE-AUTORUN", rel, 0,
                          ".vscode task set to run on folder-open. Just opening the "
                          "project in VS Code executes it - a current Contagious Interview trick.",
                          ""))
    elif data:
        report.add(Signal(TIER_WEAK, "VSCODE-TASK", rel, 0,
                          ".vscode/tasks.json present - check what its tasks execute.", ""))

def scan_repo_structure(root, report):
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath.split(os.sep):
            dirnames[:] = []
            continue
        if os.path.basename(dirpath) == "node_modules":
            report.add(Signal(TIER_PRETEXT, "COMMITTED-NODE-MODULES",
                              os.path.relpath(dirpath, root), 0,
                              "node_modules committed to the repo - payload can hide in a "
                              "dependency you'd never audit. Delete and reinstall clean.", ""))
            dirnames[:] = []

# =============================================================================
# Driver + output
# =============================================================================

def run(root):
    report = Report(root=root)
    scan_repo_structure(root, report)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in TEXT_EXTS or name in {"tasks.json", "package.json"}:
                full = os.path.join(dirpath, name)
                analyze_file(full, os.path.relpath(full, root), report)
    return report

COLOR = {"CRITICAL": "\033[41m\033[97m", "HIGH": "\033[91m", "SUSPICIOUS": "\033[93m",
         "LOW": "\033[92m", TIER_SMOKING: "\033[41m\033[97m", TIER_STRONG: "\033[91m",
         TIER_PRETEXT: "\033[93m", TIER_WEAK: "\033[90m", "R": "\033[0m", "B": "\033[1m"}

def col(key, s, on):
    return f"{COLOR.get(key,'')}{s}{COLOR['R']}" if on else s

def print_report(report, on):
    verdict, blurb = report.verdict()
    order = {TIER_SMOKING: 0, TIER_STRONG: 1, TIER_PRETEXT: 2, TIER_WEAK: 3}
    sigs = sorted(report.signals, key=lambda s: (order.get(s.tier, 9), s.path, s.line))

    print()
    print(col("B", "  beavertrap  -  recruiter-scam (Contagious Interview) detector", on))
    print(f"  target: {report.root}")
    print("  " + "=" * 70)
    print(col(verdict, f"  VERDICT: {verdict}   (signal score {report.score()})", on))
    print(f"  {blurb}")
    print("  " + "=" * 70)

    if not sigs:
        print("  No family signatures matched.")
    else:
        for s in sigs:
            tag = col(s.tier, f"[{s.tier}]", on)
            loc = s.path + (f":{s.line}" if s.line else "")
            dec = col(TIER_STRONG, "  <-- hidden; found only after de-obfuscation", on) if s.decoded else ""
            print(f"\n  {tag} {s.code}{dec}")
            print(f"      {loc}")
            print(f"      {s.message}")
            if s.snippet:
                print(f"      > {s.snippet}")
    print()
    print("  " + "-" * 70)
    print(col("B", "  IF THE VERDICT IS HIGH OR CRITICAL:", on))
    print("    - Do NOT run it, npm install it, or open it in an editor with autorun.")
    print("    - If you ALREADY ran it: assume compromise. From a DIFFERENT device,")
    print("      move any crypto to a fresh wallet with a new seed, rotate passwords,")
    print("      revoke API keys/tokens, and wipe/reimage the machine.")
    print()
    print(col("B", "  ALWAYS:", on))
    print("    A LOW verdict is NOT a safety guarantee - it means no signature matched.")
    print("    Real malware evolves to evade tools like this. Run untrusted repos only")
    print("    in a disposable, network-isolated VM. `npm install --ignore-scripts`.")
    print("    A recruiter who pressures you to run code fast IS the red flag.")
    print()

def main(argv=None):
    ap = argparse.ArgumentParser(description="Detector tuned for the fake-recruiter coding-test scam.")
    ap.add_argument("path")
    ap.add_argument("--json", metavar="FILE")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args(argv)
    if not os.path.isdir(a.path):
        print(f"error: not a directory: {a.path}", file=sys.stderr)
        return 3
    report = run(os.path.abspath(a.path))
    on = sys.stdout.isatty() and not a.no_color
    print_report(report, on)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            v, b = report.verdict()
            json.dump({"root": report.root, "verdict": v, "blurb": b,
                       "score": report.score(),
                       "signals": [asdict(s) for s in report.signals]}, fh, indent=2)
        print(f"  (JSON written to {a.json})\n")
    v, _ = report.verdict()
    return {"CRITICAL": 2, "HIGH": 1}.get(v, 0)

if __name__ == "__main__":
    sys.exit(main())
