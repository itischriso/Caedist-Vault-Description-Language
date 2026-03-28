# CVDL Planning Notes

This document keeps the rougher thinking visible.

It is not the canonical spec. The canonical documents are:

- `README.md` for what the package is and how to use it
- `DESIGN.md` for the design principles currently being defended

This file exists to preserve the design pressure that came from actually writing `.caedist` files. In this project, usability is born at the script layer first. If a feature feels awkward in the `.caedist` file, that awkwardness matters.

## Why The `.caedist` File Leads

The language is not being designed from an abstract grammar outward. It is being shaped by real deployment scripts.

The practical test is:

- can an operator read the script and understand the intended topology
- can the script express the required Vault lifecycle without shell folklore
- can the script be reduced for smaller tasks like warm start, bounce, or single-purpose bring-up

If the answer is no, the language shape is wrong even if the parser can technically support it.

## Current Language Shape

The strongest parts of the language so far are:

- collections as the core abstraction
- targeted operators for additive mutation
- explicit lifecycle verbs
- small control-flow surface
- keeping destructive teardown out of the language

The key principle is that a singleton is still a collection. That keeps the execution model consistent.

## Why Collections Matter

The language uses:

```caedist
default_vaults().deploy
```

instead of introducing one model for singleton work and another for multi-vault work.

That means:

- one vault can still be expressed as a collection
- six vaults do not require a different mental model
- reduced scripts stay readable
- scaling up does not require redesigning the syntax later

## Why Targeted Operators Matter

The split between:

```caedist
collection().method
```

and:

```caedist
action.role(*target)
```

is one of the most important language decisions.

This keeps:

- bulk orchestration separate from singular mutation
- baseline deployment separate from specialization
- the parser simple enough to reason about

It also gives the language its own identity. Without this split, it would collapse back into a pile of scripts with punctuation.

## Blank-Slate Deployment

The runner deploys generic baseline vaults first and then mutates them into more specialized roles.

That is intentional.

Reasons:

- it avoids hardcoding every deployment path into the initial scaffold
- it makes role upgrades composable
- it keeps the baseline executor deterministic
- it is easier to understand and debug than many specialized one-off deploy flows

This is especially important for:

- unsealer vaults
- unsealer subscribers
- TLS enablement
- PKI-related changes

## Secure Storage Notes

`secure_storage` is a constrained setting, not a free-form mode string.

The intended forms are:

```caedist
secure_storage = "nosave"
secure_storage = "file"
secure_storage = "encrypted_file"
secure_storage = "vault=http://127.0.0.1:9500"
```

Current thinking:

- `nosave` is the safest development option when manual handling is acceptable
- `file` is intentionally unsafe and should say so loudly
- `encrypted_file` is desirable but still TODO
- `vault=...` is powerful because a smaller script could stand up a dedicated Vault for Shamir key escrow

That last point is important enough to preserve in the docs:

- a smaller `.caedist` script could stand up a permanent or throw-away storage Vault
- this is operationally useful
- it is also dangerous because centralizing bootstrap material weakens the point of Shamir splitting if done carelessly

## Ring 0 And Outer Rings

Not everything belongs in ring 0.

Current separation:

- ring 0: deploy, start, init, unseal, login, credential handling, transit subscription, TLS transition, bounce
- outer ring: PKI rebuild helper, richer certificate workflows, more specialized operations

This is partly about stability and partly about blast radius.

The interactive terminal launcher is also intentionally outside the core evaluator logic in structural terms. It is an adapter, not the orchestration model.

PKI may stay outside ring 0 permanently. That is not necessarily a weakness. PKI is exactly the kind of capability that can benefit from remaining modular.

## Things That Feel Native

These read naturally in CVDL:

```caedist
default_vaults().deploy
add_role.unsealer(*system-unsealer)
unsealer_subscriber(*system).subscribeTo(*system-unsealer)
transform(*system -> tls_enabled)
```

They fit the language because they read like operator actions over named infrastructure.

## Things That Feel Slightly Jarring

This works, but feels more like an API bridge than native CVDL:

```caedist
pki_build(root: *root-ca, intermediate: *intermediate-ca)
```

Why it stands out:

- it uses named parameter syntax
- it looks more like a function call than an operator statement
- it bridges into another subsystem rather than feeling like a native orchestration sentence

That does not mean it is wrong. It just means it should be treated honestly as a boundary point.

## Warm Start And Reduced Scripts

One of the strongest signs that the language is working is that reduced scripts are useful.

For example:

- warm start
- status-only runs
- bounce flows
- subset collection work
- targeted restarts

If a smaller script is easy to write and easy to understand, the language is doing its job.

## Notes On Destructive Actions

Destructive teardown should stay outside the language.

Reasoning:

- overwriting generated config is recoverable
- nuking Vault storage is not
- the DSL should build and transform
- destructive reset should remain an explicit separate action

That boundary is a safety choice, not an attempt to overprotect operators.

## Documentation Strategy

Current intended split:

- `README.md`: public overview and usage
- `DESIGN.md`: durable language/runtime principles
- `PLANNING.md`: rough thinking, tensions, and language-shape notes
- example `.caedist` files: executable examples that teach by showing the interface directly

## Near-Term TODOs

- complete `encrypted_file`
- keep refining public example comments so they teach the flow clearly
- decide whether `pki_build(...)` remains as-is or is eventually expressed in a more native form
- document release authenticity workflow with checksums and signatures

## Done Enough For Now

This project does not need to become a forever-platform before it is useful.

It is allowed to be:

- focused
- narrow
- publishable
- still evolving

That is enough.
