# Caedist Vault Description Language (CVDL) - Design Principles

This document outlines the core architectural and design decisions for the `.caedist` language and its execution engine.

## 1. Collection Operators vs. Targeted Operators

The language explicitly separates commands into two distinct categories to prevent ambiguity and keep the parser simple.

### Collection Operators
Collection operators act on an entire group of defined vaults simultaneously. 
*   **Syntax:** `collection_name().method`
*   **Example:** `default_vaults().deploy` or `default_vaults().start`
*   **Rule:** Collection methods *never* accept arguments to filter the collection. `default_vaults()` always implies "all members of the `default_vaults` collection." 

If you need to operate on a subset of vaults, you must either define a new, smaller collection block or use a targeted operator.

### Targeted Operators
Targeted operators are used to inject capabilities, mutate configuration (HCL), or define dependencies on a specific, singular vault instance.
*   **Syntax:** `action.role(*target_alias)`
*   **Example:** `add_role.unsealer(*system-unsealer)`
*   **Rule:** Targeted operators act on the specific alias provided. They represent additive, modular changes applied to a generic baseline vault.

## 2. No Implicit Dependencies

The execution engine will **never** auto-create, auto-enable, or auto-configure external dependencies. This includes:
- Secrets engines (KV, PKI, Transit, etc.)
- Auth methods (token, approle, userpass, etc.)
- External vaults or services
- Upstream PKI or unsealer configurations

If a dependency is missing, the operation **fails with a clear error**. The tool only manages the universe it was explicitly asked to create - nothing more.

**Rationale:** 
- Implicit side-effects destroy reproducibility and violate the principle of least surprise
- Changes outside the declared scope may require Change Request (CR) approval in production environments
- The tool only has authorization to modify what was explicitly declared in the `.caedist` file
- If the operator didn't declare it, we don't touch it - "let the building burn" rather than make unauthorized changes

## 3. Additive Deployment (The "Blank Slate" Rule)

To avoid complex deployment paths and hardcoded edge cases, **every** vault defined in a collection is initially deployed identically: as a generic, unsealed-via-shamir, HTTP-only instance. 

All domain-specific configurations (PKI, Transit, TLS) are treated as "upgrades" or "roles" that are injected into the running generic vault via targeted operators (e.g., `add_role`). The execution engine calculates the dependency graph and bounces the vault to apply the final state.


## 4. Secure Storage

Secure_storage is not “mode plus arbitrary payload.” It is a parameterized setting where:

nosave has no parameters
file has no parameters -- saves in the same location as the .hcl file   
encrypted_file has no parameters -- saves in the same location as the .hcl file 
vault requires parameters

So the valid forms are effectively:

secure_storage = "nosave"
secure_storage = "file"
secure_storage = "encrypted_file"
secure_storage = "vault=..."