# AI Factory Demo Target

This repository is the **target** for the YubiKey-Gated AI Factory webinar demo.

It contains intentionally incomplete code. The AI Factory agent implements it
autonomously after a human authorizes the task by touching a YubiKey.

## What's here

- `risk_scorer.py` — stub function waiting to be implemented by the agent
- `tests/` — placeholder (agent will add tests here)

## How the demo works

```
# On the factory host (yubikey-gated-ai-factory repo):
make demo-build   # sign with YubiKey → spawn Claude Code agent → agent opens PR here
make demo-ship PR=<n> SPEC_HASH=sha256:<hash>  # sign → merge with RDT commit trailer
```

The resulting merge commit contains a cryptographic chain-of-custody trailer:
- Who authorized the build (principal)
- What spec they signed (intent hash)
- Which hardware key was used (YubiKey cert chain)
- When it was authorized (timestamp + nonce)

## Branch protection (required)

This repo must have **merge commits only** enabled (no squash, no rebase).
Squash/rebase merge changes the commit SHA, breaking the chain-of-custody record.

Settings → General → Pull Requests:
- [x] Allow merge commits
- [ ] Allow squash merging  ← must be OFF
- [ ] Allow rebase merging  ← must be OFF