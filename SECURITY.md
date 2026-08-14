# Security Policy

## Supported versions

The project is pre-1.0. Only the latest released version receives security
fixes.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a vulnerability

Please do **not** open a public issue.

Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/UnspendableLabs/Kontor-Storage-Node/security/advisories/new).

Include what you can of the following — a report with a reproduction is worth
several without one:

- The version or commit you tested.
- What an attacker gains, and what access they need to start.
- Steps to reproduce, or a proof of concept.

We aim to acknowledge a report within three working days and to have an
assessment back to you within ten. If a fix is warranted we will agree a
disclosure date with you, and credit you in the advisory unless you would
rather we did not.

## What is in scope

This repository: the node binary, its HTTP server, the operator UI at
`/admin`, and the sealed channel that carries secrets between them. The
keystore and the identity derivation are the parts we care most about.

The Kontor Portal, the `kontor-crypto` crate and the Horizon Wallet are
separate projects with their own reporting channels.

## Known operational hazards

These are documented behaviours rather than vulnerabilities, but they are the
things that get node operators into trouble:

- **`ADMIN_PASSWORD` is the only credential between the internet and a
  database wipe.** Leaving it unset disables the operator UI entirely, which is
  the safe default. Setting it means choosing a real password and terminating
  TLS in front of the node.
- **The seal key unlocks the keystore.** Moving it into the environment so an
  unattended node restarts on its own trades a manual unlock for a secret
  sitting in your process environment. The README's hardening section spells
  out the trade.
- **Losing the mnemonic loses the node's identity.** There is no recovery path
  that does not go through it.
