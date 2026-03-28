# Requirements Document

## Specification
- Spec name: `cvdl-application-behavior`
- Scope: Reverse-engineered requirements for the currently implemented Caedist Vault Description Language application
- Source inputs:
  - `README.md`
  - `DESIGN.md`
  - `PLANNING.md`
  - `caedist_runner.py`
  - `vault_pki_doer.py`
  - `terminal_launcher.py`
  - `vault-description-language.caedist`
  - `warm-start.caedist`

## Purpose
This specification captures the intended functionality currently expressed by the codebase. It defines what the application is expected to do for operators who use a `.caedist` script to stand up, evolve, and inspect a declared local HashiCorp Vault topology.

## Codebase Findings
- The application is a Python CLI interpreter for a small DSL focused on local Vault topology orchestration.
- The core abstraction is a named collection of vault definitions, where each member is declared as `alias`, `port`, and `directory`.
- The runtime supports two execution styles:
  - collection-wide lifecycle methods such as `deploy`, `start`, `init`, `unseal`, `login`, `status`, `save_to_ram[]`, and `savecreds()`
  - targeted single-vault actions such as `start(*alias)`, `stop(*alias)`, `tls_enable(*alias)`, `add_role.unsealer(*alias)`, and `unsealer_subscriber(*alias).subscribeTo(*other)`
- Secure bootstrap credential handling is explicit and mode-driven through `secure_storage`.
- PKI rebuild and verification are intentionally delegated to `vault_pki_doer.py` instead of being implemented directly inside the DSL runtime.
- The current implementation supports warm-start and bounce-style scripts in addition to full bring-up scripts.
- The current implementation does not fully implement `encrypted_file` credential persistence.

## User Stories
- As a Vault operator, I want to describe a local Vault topology in a compact DSL so that I can execute repeatable bring-up and mutation workflows from one script.
- As a Vault operator, I want one abstraction for both single-vault and multi-vault orchestration so that reduced scripts and full topologies use the same mental model.
- As a Vault operator, I want explicit lifecycle commands for declared vault collections so that deploy, start, initialize, unseal, login, and status checks happen in a predictable order.
- As a Vault operator, I want targeted role and configuration mutations for individual vaults so that I can evolve generic baseline vaults into unsealers, subscribers, and TLS-enabled services.
- As a Vault operator, I want bootstrap credential handling to be explicit so that I can choose whether credentials remain in RAM, are written to files, or are pushed to another Vault.
- As a Vault operator, I want PKI rebuild work to stay outside the core DSL runtime so that the language remains focused on topology orchestration and the PKI workflow can evolve independently.
- As a Vault operator, I want reduced scripts such as warm starts and bounce flows so that I can perform partial operational workflows without replaying the entire bootstrap process.

## Functional Requirements

### REQ-001 Script Input And Parsing
The application shall accept a `.caedist` script file and parse the currently supported DSL constructs into an executable internal representation.

#### Acceptance Criteria
- WHEN the operator runs `python3 caedist_runner.py <script-path>` with an existing script, THEN the application SHALL read the file, tokenize it, build an AST, print token and AST debug output, and execute the AST in order.
- WHEN a script contains comments beginning with `;` or `#`, THEN the parser SHALL ignore those comments.
- WHEN a script contains supported statements for local assignment, global assignment, collection definitions, collection operations, targeted operations, targeted methods, `switch`, `foreach`, `emit_to_screen`, `spawn_terminal[...]`, `pki_build(...)`, or `transform(...)`, THEN the parser SHALL recognize those statements.
- IF the script path does not exist, THEN the application SHALL fail before execution with a file-not-found error.
- IF the script contains unsupported or malformed syntax, THEN the application SHALL stop parsing and report a syntax or tokenization error.

### REQ-002 Topology Declaration Through Collections
The application shall use collections as the primary way to declare Vault topology members and to drive collection-wide orchestration.

#### Acceptance Criteria
- WHEN a script defines a collection with repeated `alias`, `port`, `directory` triplets, THEN the runtime SHALL store each triplet as one vault member in the named collection.
- WHEN a collection contains one member, THEN the application SHALL still treat it as a collection and allow collection operations on it.
- WHEN a script declares `@Single_vault_root`, THEN deployment and file-based operations SHALL resolve vault directories relative to that root.
- IF a collection operation references an undefined collection, THEN the runtime SHALL skip the operation and report that the collection is undefined.

### REQ-003 Baseline Vault Lifecycle Orchestration
The application shall provide collection-wide lifecycle methods for bringing up and inspecting a declared Vault topology.

#### Acceptance Criteria
- WHEN the operator executes `collection().deploy`, THEN the application SHALL create each vault directory, create a `data/` subdirectory, and write a generic HTTP `vault.hcl` file for each declared vault member.
- WHEN the operator executes `collection().start`, THEN the application SHALL launch `vault server -config=<vault.hcl>` for each declared vault and retain process handles for later stop operations.
- WHEN the operator executes `collection().stop`, THEN the application SHALL terminate tracked processes started by the current runtime session.
- WHEN the operator executes `collection().init`, THEN the application SHALL call `vault operator init -format=json` against each declared vault, cache the unseal keys and root token in memory, and surface the captured credentials to operator output.
- WHEN the operator executes `collection().unseal`, THEN the application SHALL use the cached Shamir keys to submit three unseal operations per vault when at least three keys are present.
- WHEN the operator executes `collection().login`, THEN the application SHALL use the cached root token to perform `vault login` for each vault with available credentials.
- WHEN the operator executes `collection().status`, THEN the application SHALL query `vault status -format=json` and report whether each vault is sealed or unsealed.
- IF a lifecycle step depends on credentials that are not present in memory, THEN the application SHALL skip that vault and report the missing credential condition instead of inventing replacement data.

### REQ-004 Explicit Credential Handling Modes
The application shall make post-initialization credential handling explicit through the `secure_storage` setting.

#### Acceptance Criteria
- WHEN `secure_storage` is evaluated through `switch(secure_storage)`, THEN the runtime SHALL split the configured value into a storage mode and an optional payload using the first `=` character.
- WHEN the selected mode is `nosave`, THEN the application SHALL preserve credentials in runtime memory and allow the script to continue without writing bootstrap credentials to disk.
- WHEN the selected mode is `file` and the script later invokes `collection().savecreds()`, THEN the application SHALL write per-vault `init_keys.json` files containing the first five unseal keys and the root token and SHALL attempt to restrict those files to owner-only permissions.
- WHEN the selected mode is `vault=<addr>` and the script later invokes `collection().savecreds()`, THEN the application SHALL write each vault's bootstrap credentials to `kv/data/<alias>` on the target Vault using the Vault CLI.
- IF a `vault=<addr>` storage operation is requested without a usable target token already in the environment, THEN the application SHALL prompt the operator for a Vault token.
- WHEN the selected mode is `encrypted_file`, THEN the application SHALL currently treat the flow as not yet implemented rather than silently pretending encrypted persistence exists.

### REQ-005 Manual Operator Assistance
The application shall support explicit manual follow-up workflows for operators after bootstrap.

#### Acceptance Criteria
- WHEN a script calls `emit_to_screen("...")`, THEN the runtime SHALL print the message to operator output.
- WHEN a script calls `emit_to_screen(collection().save_to_ram[])`, THEN the runtime SHALL show which vault aliases currently have credentials cached in memory.
- WHEN a script iterates `foreach <var> in <collection>`, THEN the runtime SHALL bind the loop variable to each vault alias and execute the loop body once per collection member.
- WHEN a script calls `spawn_terminal[alias-or-loop-var]`, THEN the runtime SHALL open an OS-specific terminal window for the resolved vault alias with `VAULT_ADDR` preset and the vault directory selected as the working directory.
- IF the target alias for `spawn_terminal[...]` cannot be resolved from the declared topology, THEN the runtime SHALL report an error instead of opening an unrelated terminal.

### REQ-006 Targeted Role Mutation And Transit Auto-Unseal
The application shall support targeted single-vault mutations that convert generic baseline vaults into explicit operational roles.

#### Acceptance Criteria
- WHEN the operator executes `add_role.unsealer(*alias)`, THEN the application SHALL enable the transit secrets engine on the targeted vault and create an `autounseal` transit key using the targeted vault's cached root token.
- WHEN the operator executes `add_role.unsealer_subscriber(*alias)`, THEN the application SHALL acknowledge that the targeted vault is intended to behave as an unsealer subscriber and allow later subscriber-specific methods to target that alias.
- WHEN the operator executes `unsealer_subscriber(*subscriber).subscribeTo(*unsealer)`, THEN the application SHALL create a policy on the unsealer, create a periodic orphan token for the subscriber, and append a transit seal block to the subscriber's `vault.hcl`.
- WHEN the operator executes `unsealer_subscriber(*subscriber).migrate`, THEN the application SHALL use the subscriber's cached Shamir keys to run `vault operator unseal -migrate` operations.
- IF a targeted role or targeted method references an alias that is not part of the declared topology, THEN the runtime SHALL report the missing target and SHALL NOT mutate another vault.
- IF transit setup or migration requires a root token or unseal keys that are not cached in memory, THEN the runtime SHALL stop that targeted action and report the missing prerequisites.

### REQ-007 Targeted Runtime Control And TLS Transition
The application shall support single-vault runtime control and a staged transition from HTTP to HTTPS.

#### Acceptance Criteria
- WHEN the operator executes `start(*alias)` or `stop(*alias)`, THEN the runtime SHALL start or stop only the targeted vault process tracked in the current session.
- WHEN the operator executes `tls_enable(*alias)`, THEN the application SHALL update the targeted vault's `vault.hcl` listener block to enable TLS and SHALL switch `api_addr` from `http://` to `https://`.
- WHEN the operator executes `transform(*alias -> tls_enabled)`, THEN the runtime SHALL update its internal state so later Vault CLI operations target the vault over HTTPS and can use a per-vault CA chain if present.
- IF `tls_enable(*alias)` is called before the target vault has a deployed `vault.hcl`, THEN the runtime SHALL fail that action with a clear error.
- IF a targeted runtime command references an undeclared alias, THEN the runtime SHALL report the missing target and SHALL NOT act on another vault.

### REQ-008 Externalized PKI Workflow
The application shall keep PKI rebuild work in a separate helper while still allowing the DSL runtime to orchestrate that helper.

#### Acceptance Criteria
- WHEN the operator executes `pki_build(root: *rootAlias, intermediate: *intermediateAlias)`, THEN the runtime SHALL invoke `vault_pki_doer.py rebuild-pki` with the declared topology, the selected root and intermediate aliases, the vault root path, and any cached root tokens available in memory.
- WHEN the PKI helper runs `plan-rebuild`, THEN it SHALL describe the rebuild phases without changing Vault state.
- WHEN the PKI helper runs `rebuild-pki`, THEN it SHALL enable and tune PKI mounts, generate the root CA, generate and sign the intermediate CSR, configure PKI URLs, create listener roles, issue listener certificates, and write artifacts under the configured artifact and cert directories.
- WHEN the PKI helper runs `verify-pki`, THEN it SHALL verify PKI mount readability and certificate file presence for the declared topology.
- WHEN the PKI helper runs `teardown-pki`, THEN it SHALL disable the PKI mounts and remove PKI artifact directories.
- WHEN the PKI helper completes `rebuild-pki`, THEN restart and cutover decisions SHALL remain manual rather than being performed automatically by the helper.

### REQ-009 Reduced Operational Scripts
The application shall support partial scripts that reuse the same DSL surface for narrower operational workflows.

#### Acceptance Criteria
- WHEN the operator provides a reduced script containing only a subset of the supported constructs, THEN the runtime SHALL execute only the declared steps in the written order.
- WHEN a script performs a warm start flow such as `collection().start` followed by `collection().status`, THEN the application SHALL support that flow without requiring deploy or init to be repeated first.
- WHEN a script performs a bounce-style sequence of targeted `stop` and `start` calls, THEN the runtime SHALL support that sequence on the declared aliases without requiring a different execution mode.

### REQ-010 Safety Boundaries And Explicit Scope
The application shall keep destructive or out-of-scope behavior outside the DSL and shall only act on explicitly declared topology members.

#### Acceptance Criteria
- WHEN the runtime performs deploy or mutation work, THEN it SHALL limit that work to the vault aliases and paths declared in the active script.
- IF a required dependency or prerequisite has not been explicitly established by earlier script steps, THEN the runtime SHALL report the failure state instead of auto-discovering or auto-creating unrelated external systems.
- WHEN operators need destructive teardown of Vault storage or topology, THEN that action SHALL remain outside the DSL's supported orchestration surface.

## Assumptions And Constraints
- The application targets local or operator-managed Vault processes rather than remote managed services.
- The runtime depends on the `vault` CLI being installed and available on `PATH`.
- The runtime depends on Python 3.10+ and currently uses only the Python standard library.
- Interactive terminal spawning requires a supported terminal emulator on the current operating system.
- The current implementation is oriented around explicit operator sequencing rather than background reconciliation.
- `encrypted_file` persistence is intentionally incomplete in the current implementation and should be treated as a known gap rather than as delivered functionality.

## Non-Goals
- General-purpose infrastructure orchestration beyond the declared Vault topology
- Implicit destructive teardown of Vault data directories
- Automatic reconciliation of missing external dependencies not explicitly invoked by the script
- Hiding bootstrap credential handling behind implicit defaults

## Validation Summary
Manual validation against the current codebase indicates this requirements document:
- uses reverse-engineered, operator-facing user stories
- maps each major implemented behavior to explicit acceptance criteria
- captures major current limitations and non-goals
- aligns with the existing repository design principle that collections are primary and destructive teardown stays outside the DSL

## Code Vs Spec Status

### Implemented With Good Confidence
- `REQ-001` basic tokenization, parsing, AST construction, and execution entrypoint
- `REQ-002` collection declaration and collection-based topology storage
- `REQ-003` local deploy, start, stop, init, unseal, login, and status command paths
- `REQ-005` `emit_to_screen`, `foreach`, and `spawn_terminal[...]`
- `REQ-006` `add_role.unsealer`, subscriber linking, and migration command paths
- `REQ-007` targeted start, stop, `tls_enable`, and `transform(... -> tls_enabled)`
- `REQ-009` reduced-script execution model
- `REQ-010` explicit-scope behavior and lack of destructive topology teardown in the DSL runtime

### Partially Implemented Or Fragile
- `REQ-001`: parser support is real but narrow; some forms are accepted only in exact currently implemented syntax.
- `REQ-004`: `file` and `vault=<addr>` flows exist under `collection().savecreds()`, but `encrypted_file` falls back to stub behavior.
- `REQ-004`: file permission hardening uses `chmod(0o600)`, which is attempted on Windows but is not a strong cross-platform guarantee.
- `REQ-005`: `emit_to_screen(collection().save_to_ram[])` is special-cased by the evaluator rather than being a general expression engine.
- `REQ-006`: `add_role.unsealer_subscriber(*alias)` is acknowledgement-only and does not persist a role model beyond operator output.
- `REQ-007`: HTTPS cutover relies on `transform(*alias -> tls_enabled)` after `tls_enable(*alias)`; `tls_enable` alone updates config but does not flip runtime addressing.
- `REQ-008`: the DSL runtime only orchestrates `rebuild-pki`; `plan-rebuild`, `verify-pki`, and `teardown-pki` exist in the helper CLI but are not exposed as DSL statements.

### Not Implemented Or Intentionally Stubbed
- `REQ-004`: true `encrypted_file` persistence
- General DSL support for PKI helper commands beyond `pki_build(...)`
- Any automatic restart or cutover after PKI rebuild

### Ambiguities To Keep In Mind
- The switch parser accepts `default` using the same parse path as `case`, which makes the implementation more permissive and more awkward than the prose suggests.
- `collection().savecreds()` is implemented as a collection method name, but the README examples focus more heavily on `save_to_ram[]`.
- Process tracking is session-scoped only; stop operations cannot recover handles for Vault processes started outside the current interpreter run.
