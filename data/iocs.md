# beavertrap IOCs — Contagious Interview / BeaverTail / InvisibleFerret

> **Dated: 2026-08-29.** **Network indicators decay fast.** IPs, domains, and
> specific malicious package names below rotate within *weeks* as the operators
> move infrastructure — treat any such value as historical, not a live
> blocklist. The **durable** indicators — wallet browser-extension IDs, the
> `:1224` + `/pdown`-style URL-path patterns, ports, and obfuscation/decoder
> patterns — age slowly because they are tied to how the malware works, not
> where it is hosted. beavertrap leans on the durable ones by design.
>
> This file mirrors indicators **already encoded in `beavertrap.py`** (sourced
> from the published reporting credited in the README) and marks everything
> else as `TODO`. **Do not add fabricated values.** Only add an indicator with
> a citation to public reporting, and only after confirming it. Prefer inert
> descriptions over live values.

---

## Wallet extension IDs (durable)

Chrome/Brave wallet extension IDs BeaverTail enumerates to locate and drain
wallets. Mirrored from `KNOWN_WALLET_EXT_IDS` in `beavertrap.py`; verify each
against current vendor listings before citing.

| Extension ID (32-char `a–p`)       | Wallet            |
| ---------------------------------- | ----------------- |
| `nkbihfbeogaeaoehlefnkodbefgpgknn` | MetaMask          |
| `fhbohimaelbohpjbbldcngcnapndodjp` | BNB Chain Wallet  |
| `hnfanknocfeofbddgcijnmhnfnkdnoad` | Coinbase Wallet   |
| `bfnaelmomeimhlpmgjnjophhpkoljnlb` | Phantom           |
| `ibnejdfjmmkpcnlpebklmnkoeoihofec` | TronLink          |
| `aeachknmefphepccionboohckonoeemg` | Coin98            |
| `egjidjbpglichdcondbcbdnbeeppgdph` | Trust Wallet      |
| `nphplpgoakhhjchkkhmiggakijnkhfnd` | Ton Wallet        |
| `fnjhmkhhmkbjkkabndcnnogagogbneec` | Ronin Wallet      |
| `hpglfhgfnhbgpjdenjgmdgoeiappafln` | Guarda / Argent   |
| `afbcbjpbpfadlkmhmclhkeeodmamcflc` | Math Wallet       |

> Generic shape also matched: a 32-character all-lowercase `a–p` token;
> several enumerated together is the tell. The malware's targeted-wallet list
> grows over time (reported at 9 → 13 → 22 → 43+ across samples) — expect
> additions. `TODO: reconcile this table against the latest published list.`

## C2 ports & URL paths (durable)

Mirrored from the C2 detectors in `beavertrap.py`.

- **Port:** `1224` (BeaverTail → Python second-stage / InvisibleFerret).
- **URL-path shapes:** `/pdown`, `/client/<id>`, `/uploads/`, `/keys/`, `/adc`,
  `/payload`.
- **Specific C2 IPs / hosts:** `TODO — volatile, decays within weeks. Add only
  current, cited values; do not fabricate. Leave empty rather than guess.`

## Malicious package names (volatile)

npm / PyPI package names used as lures or droppers.

- `TODO — volatile. Populate from current Socket / published advisories with a
  citation per entry. Do not invent package names.`

## File hashes (volatile)

- `TODO — SHA-256 hashes for known BeaverTail / InvisibleFerret samples. Add
  only hashes copied from published reporting, each with its source. Do NOT
  fabricate hashes and do NOT commit real samples to obtain them.`

## File / path artifacts (mixed)

Durable structural artifacts beavertrap already keys on:

- `.vscode/tasks.json` containing `runOn: folderOpen` (autorun on folder open).
- `package.json` lifecycle hooks: `preinstall` / `install` / `postinstall` /
  `prepare` / `prepublish` — especially when they shell out or fetch remote code.
- Non-registry dependencies (`git+…`, `http(s)…`, `file:…`, `github:…`, `.tgz`).
- Solana keypair theft: reads of `~/.config/solana/id.json`.
- Browser credential stores: `Login Data`, `Local State`, `Cookies`, leveldb
  `.ldb`, `login.keychain`; SSH keys `id_rsa` / `id_ed25519`.
- AnyDesk / unattended-access references (remote-control persistence).
- Committed `node_modules/` (payload hidden in a dependency you would not audit).
- `TODO — add any additional dropped-file paths / staging dirs from current
  reporting, with citations.`

## Obfuscation patterns (durable)

Mirrored from the deobfuscation and obfuscation detectors in `beavertrap.py`.

- `\xNN` hex-escape string tables (runs of 8+); `\uNNNN` unicode runs (6+).
- `javascript-obfuscator` / obfuscator.io signature: `_0xabcd`-style hex-named
  identifiers, large string arrays.
- Base64 blobs that decode to mostly-printable text.
- IOCs split across concatenated string literals (`"nkbi" + "hfbe" + …`).

## Delivery TTPs (durable)

- Fake recruiter / hiring pretext; "take-home assignment" delivered as a GitHub
  repo or zip; request to record a Loom/video walkthrough.
- Time pressure to run the code quickly ("other candidates lined up").
- Instruction to `npm install` then `npm start`, or to open the folder in an
  IDE — triggering install hooks or the `.vscode` autorun task.
- `TODO — add current lure platforms / persona details from published reporting,
  with citations. Keep persona specifics sourced, not speculative.`

---

### Sources

Indicators here operationalize **published** research; beavertrap claims no
original attribution. `TODO — add the specific report URLs` from: Palo Alto
Unit 42, Socket, ESET, Group-IB, Cisco Talos, Microsoft, Datadog, Silent Push.
