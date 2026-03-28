# Caedist Vault Description Language (CVDL)

CVDL is a purpose-built DSL for standing up and evolving a specific HashiCorp Vault topology with repeatable, explicit steps.

It is not a general infrastructure platform. It exists to do one job well: build the Vault layout you describe, in the order you describe it, with as little accidental complexity as possible.

## What It Does

- Deploys a baseline collection of Vault instances as generic HTTP, Shamir-sealed vaults.
- Starts, initializes, unseals, logs into, stops, and checks status for vault collections.
- Stores bootstrap credentials in RAM, plain files, or another Vault, depending on `secure_storage`.
- Opens operator terminals for manual follow-up where needed.
- Applies targeted role mutations such as unsealer and unsealer subscriber behavior.
- Wires transit auto-unseal subscriptions and performs migration from Shamir to transit seal.
- Delegates PKI rebuild work to `vault_pki_doer.py` rather than mixing PKI complexity into ring 0.
- Supports reduced scripts for warm starts and bounce workflows.

## Design Goals

- Collections are the core abstraction. A singleton is still a collection.
- `collection().method` acts on every member of the named collection.
- `action.role(*target)` applies a targeted additive mutation to one vault.
- The engine never auto-creates undeclared external dependencies.
- Baseline deployment is authoritative and intentionally overwrites generated config.
- Destructive teardown is kept outside the language on purpose.

See [DESIGN.md] for the governing design principles.

## Package Contents

- [caedist_runner.py]: lexer, parser, AST, evaluator, and runtime.
- [terminal_launcher.py]: OS-specific interactive terminal launcher.
- [vault_pki_doer.py]: standalone PKI rebuild/verify/teardown helper.
- [vault-description-language.caedist]: full topology example.
- [warm-start.caedist]: reduced warm-start example.

## Requirements

- Python 3.10+
- HashiCorp Vault CLI on `PATH`
- A local Vault binary compatible with `vault server`, `vault operator`, `vault write`, `vault read`, and `vault status`
- On Linux, one of: `gnome-terminal`, `konsole`, `xfce4-terminal`, or `xterm`
- On Windows, Windows Terminal (`wt`) for `spawn_terminal`

Python package dependencies are stdlib-only. See [requirements.txt].

## Installation

```bash
git clone <repo-url>
cd caedist-vault-description-language
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
vault version
python3 caedist_runner.py --help
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
vault version
python caedist_runner.py --help
```

## Language Overview

### Global and local assignment

```caedist
secure_storage = "nosave"
@Single_vault_root = "/path/to/secure/caedist-vault/"
```

### Collections

```caedist
default_vaults = {
    "system","8900","system-vault"
    "system-unsealer","8930","system-unsealer"
}
```

Each collection member is defined as:

`"alias","port","directory"`

### Collection operators

```caedist
default_vaults().deploy
default_vaults().start
default_vaults().init
default_vaults().unseal
default_vaults().login
default_vaults().status
default_vaults().save_to_ram[]
```

Collection methods do not accept filter arguments. `collection()` always means all members.

### Targeted operators

```caedist
add_role.unsealer(*system-unsealer)
add_role.unsealer_subscriber(*system)
unsealer_subscriber(*system).subscribeTo(*system-unsealer)
unsealer_subscriber(*system).migrate
tls_enable(*system)
transform(*system -> tls_enabled)
```

### Control flow

```caedist
switch(secure_storage){
    case: nosave {
        emit_to_screen("please log into vaults manually")
    }
}
```

### Secure storage

Valid `secure_storage` forms:

- `secure_storage = "nosave"`
- `secure_storage = "file"`
- `secure_storage = "encrypted_file"`
- `secure_storage = "vault=http://127.0.0.1:9500"`

Only `vault` accepts a payload.

## Example: Full Bring-Up

The main example script is [vault-description-language.caedist]. It performs:

1. Baseline deploy of the declared topology.
2. Start, init, unseal, and login.
3. Credential handling according to `secure_storage`.
4. PKI rebuild via `vault_pki_doer.py`.
5. Transit unsealer role setup.
6. Transit subscription and migration.
7. TLS enablement and bounce.
8. Final status check.

Run it with:

```bash
python3 caedist_runner.py vault-description-language.caedist
```

## Example: Warm Start

[warm-start.caedist] starts the declared vaults and checks status without replaying the full bootstrap:

```bash
python3 caedist_runner.py warm-start.caedist
```

This is useful for bounce and restart scenarios where the topology already exists.

## PKI

PKI work is intentionally handled outside ring 0 by [vault_pki_doer.py].

Available commands include:

- `plan-rebuild`
- `teardown-pki`
- `rebuild-pki`
- `verify-pki`
- `inject-failure`

Example:

```bash
python3 vault_pki_doer.py plan-rebuild
```

The runner can invoke PKI rebuild from the DSL via:

```caedist
pki_build(root: *root-ca, intermediate: *intermediate-ca)
```

## Current Status

Implemented now:

- Collections
- Targeted operators and targeted methods
- Switch/foreach
- Warm start and bounce-oriented scripts
- Transit unseal subscription and migration
- TLS enablement transforms
- PKI helper integration

Still TODO:

- `encrypted_file` credential persistence

## Security Notes

- `deploy` intentionally overwrites generated Vault config.
- The language deliberately does not include destructive teardown.
- Credential persistence mode is explicit and operator-chosen.
- Plain file credential storage is intentionally marked unsafe.
- PKI remains outside ring 0 by design.

## Release Authenticity

If you publish releases, ship checksums for every artifact:

- `SHA256SUMS`
- optionally a detached signature for `SHA256SUMS`

Checksums are good. Signed checksums are better.

