#!/usr/bin/env python3
"""
Standalone Caedist PKI doer.

This script assumes the six-vault topology is already deployed and focuses on
PKI teardown, rebuild, validation, and controlled fault injection.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Sequence


class Colours:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    ENDC = "\033[0m"


@dataclass(frozen=True)
class VaultEndpoint:
    slug: str
    host: str
    port: int
    role: str

    @property
    def http_addr(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def https_addr(self) -> str:
        return f"https://{self.host}:{self.port}"


@dataclass(frozen=True)
class Context:
    artifacts_dir: Path
    cert_root: Path
    vault_root: Path
    root_tls: bool
    intermediate_tls: bool
    root_cacert: Path | None
    vault_bin: str
    dry_run: bool
    verbose: bool
    topology: dict[str, VaultEndpoint]
    root_ca_alias: str
    root_ca_token: str | None
    intermediate_ca_alias: str
    intermediate_ca_token: str | None


class DoerError(RuntimeError):
    pass


def print_step(message: str) -> None:
    print(f"{Colours.CYAN}{message}{Colours.ENDC}")


def print_ok(message: str) -> None:
    print(f"{Colours.GREEN}{message}{Colours.ENDC}")


def print_warn(message: str) -> None:
    print(f"{Colours.YELLOW}{message}{Colours.ENDC}")


def print_fail(message: str) -> None:
    print(f"{Colours.RED}{message}{Colours.ENDC}")


def require_binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise DoerError(f"Required binary not found on PATH: {name}")
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rebuild or tear down the Caedist Vault PKI on an already-deployed topology."
    )
    parser.add_argument("command", choices=[
        "plan-rebuild",
        "teardown-pki",
        "rebuild-pki",
        "verify-pki",
        "inject-failure",
    ])
    parser.add_argument("--artifacts-dir", type=Path, default=Path.cwd() / "pki-artifacts", help="Directory holding PKI JSON/CSR artifacts.")
    parser.add_argument("--cert-root", type=Path, default=Path.cwd() / "certstore", help="Root directory for per-vault TLS material.")
    parser.add_argument("--vault-root", type=Path, default=Path.cwd(), help="Root directory containing one folder per vault.")
    parser.add_argument("--root-tls", action="store_true", help="Root CA vault is already serving HTTPS.")
    parser.add_argument("--intermediate-tls", action="store_true", help="Intermediate CA vault is already serving HTTPS.")
    parser.add_argument("--root-cacert", type=Path, default=None, help="CA file to trust when root/intermediate are on HTTPS.")
    parser.add_argument("--vault-def", action="append", help="Define a vault endpoint. Format: slug:host:port:role. Can be repeated.")
    parser.add_argument("--root-ca-alias", help="Alias of the vault to act as root CA.")
    parser.add_argument("--root-ca-token", help="Token for the root CA vault.")
    parser.add_argument("--intermediate-ca-alias", help="Alias of the vault to act as intermediate CA.")
    parser.add_argument("--intermediate-ca-token", help="Token for the intermediate CA vault.")
    parser.add_argument("--vault-bin", default="vault", help="Vault CLI executable.")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without changing Vault state.")
    parser.add_argument("--verbose", action="store_true", help="Print commands before execution.")
    parser.add_argument("--failure-type", choices=[
        "wrong-root-protocol",
        "wrong-intermediate-protocol",
        "missing-root-cacert",
        "bad-root-cacert-path",
        "bad-intermediate-role-name",
    ], default="missing-root-cacert")
    return parser.parse_args()


def build_context(args: argparse.Namespace, topology: dict[str, VaultEndpoint]) -> Context:
    vault_bin = require_binary(args.vault_bin)
    root_cacert = args.root_cacert.resolve(strict=False) if args.root_cacert else None
    return Context(
        artifacts_dir=args.artifacts_dir.resolve(strict=False),
        cert_root=args.cert_root.resolve(strict=False),
        vault_root=args.vault_root.resolve(strict=False),
        root_tls=args.root_tls,
        intermediate_tls=args.intermediate_tls,
        root_cacert=root_cacert,
        vault_bin=vault_bin,
        dry_run=args.dry_run,
        verbose=args.verbose,
        topology=topology,
        root_ca_alias=args.root_ca_alias,
        root_ca_token=args.root_ca_token,
        intermediate_ca_alias=args.intermediate_ca_alias,
        intermediate_ca_token=args.intermediate_ca_token,
    )


def endpoint_addr(ctx: Context, slug: str) -> str:
    vault = ctx.topology[slug]
    if slug == ctx.root_ca_alias:
        return vault.https_addr if ctx.root_tls else vault.http_addr
    if slug == ctx.intermediate_ca_alias:
        return vault.https_addr if ctx.intermediate_tls else vault.http_addr
    return vault.https_addr


def env_for(ctx: Context, slug: str) -> dict[str, str]:
    env = os.environ.copy()
    env["VAULT_ADDR"] = endpoint_addr(ctx, slug)
    if env["VAULT_ADDR"].startswith("https://") and ctx.root_cacert:
        env["VAULT_CACERT"] = str(ctx.root_cacert)
    else:
        env.pop("VAULT_CACERT", None)
    env.pop("VAULT_SKIP_VERIFY", None)
    env.pop("VAULT_TOKEN", None) # Ensure we start with a clean token slate

    # Prioritize tokens passed via command line for the specific CAs
    if slug == ctx.root_ca_alias and ctx.root_ca_token:
        env["VAULT_TOKEN"] = ctx.root_ca_token
        return env
    if slug == ctx.intermediate_ca_alias and ctx.intermediate_ca_token:
        env["VAULT_TOKEN"] = ctx.intermediate_ca_token
        return env

    init_keys_path = ctx.vault_root / slug / "init_keys.json"
    if init_keys_path.exists():
        try:
            keys = read_json(init_keys_path)
            if "root" in keys:
                env["VAULT_TOKEN"] = keys["root"]
        except Exception as e:
            print_warn(f"Failed to read token from {init_keys_path}: {e}")

    return env


def run(ctx: Context, slug: str, args: Sequence[str], capture: bool = False) -> subprocess.CompletedProcess[str] | None:
    cmd = [ctx.vault_bin, *args]
    env = env_for(ctx, slug)
    if ctx.verbose or ctx.dry_run:
        env_bits = [f'VAULT_ADDR="{env["VAULT_ADDR"]}"']
        if "VAULT_CACERT" in env:
            env_bits.append(f'VAULT_CACERT="{env["VAULT_CACERT"]}"')
        print(f"  {' '.join(env_bits)} {' '.join(cmd)}")
    if ctx.dry_run:
        return None
    result = subprocess.run(
        cmd,
        cwd=ctx.artifacts_dir,
        env=env,
        text=True,
        capture_output=capture,
        check=False,
    )
    if result.returncode != 0:
        if capture:
            stderr = (result.stderr or "").strip() or (result.stdout or "").strip()
        else:
            stderr = "(output streamed to terminal)"
        raise DoerError(f"{slug}: {' '.join(args)} failed: {stderr}")
    return result


def write_json_output(ctx: Context, slug: str, args: Sequence[str], output_path: Path) -> None:
    cmd = [ctx.vault_bin, *args]
    env = env_for(ctx, slug)
    if ctx.verbose or ctx.dry_run:
        env_bits = [f'VAULT_ADDR="{env["VAULT_ADDR"]}"']
        if "VAULT_CACERT" in env:
            env_bits.append(f'VAULT_CACERT="{env["VAULT_CACERT"]}"')
        print(f"  {' '.join(env_bits)} {' '.join(cmd)} > {output_path}")
    if ctx.dry_run:
        return
    result = subprocess.run(
        cmd,
        cwd=ctx.artifacts_dir,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise DoerError(f"{slug}: {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}")
    output_path.write_text(result.stdout, encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure_directories(ctx: Context) -> None:
    if not ctx.artifacts_dir.exists():
        ctx.artifacts_dir.mkdir(parents=True, exist_ok=True)
    if not ctx.cert_root.exists():
        ctx.cert_root.mkdir(parents=True, exist_ok=True)


def assert_https_ready(ctx: Context, slug: str) -> None:
    addr = endpoint_addr(ctx, slug)
    if addr.startswith("https://") and not ctx.root_cacert:
        raise DoerError(
            f"{slug} is configured for HTTPS but no --root-cacert was provided. "
            "Use the CA trust file, not a guess."
        )


def extract_field(ctx: Context, json_path: Path, field: str, output_path: Path, append: bool = False) -> None:
    payload = read_json(json_path)
    value = payload["data"][field]
    if append and output_path.exists():
        output_path.write_text(output_path.read_text(encoding="utf-8") + value + "\n", encoding="utf-8")
    else:
        output_path.write_text(value + "\n", encoding="utf-8")


def plan_rebuild(ctx: Context) -> None:
    print_step("Planned PKI rebuild")
    print(textwrap.dedent(f"""
    Artifacts: {ctx.artifacts_dir}
    Certstore: {ctx.cert_root}
    Root addr: {endpoint_addr(ctx, ctx.root_ca_alias)}
    Intermediate addr: {endpoint_addr(ctx, ctx.intermediate_ca_alias)}

    Phases:
    1. Tune/enable root and intermediate PKI mounts if needed.
    2. Generate intermediate CSR on the intermediate CA vault.
    3. Sign the CSR on the root CA vault.
    4. Import the signed intermediate certificate.
    5. Configure issuing and CRL URLs.
    6. Create listener roles on root and intermediate.
    7. Issue listener certificates for intermediate, system, and user vaults.
    8. Write artifacts into the workspace only.
    9. Stop before restart/cutover decisions; verify manually or with verify-pki.
    """).strip())


def teardown_pki(ctx: Context) -> None:
    print_step("Tearing down PKI state")
    mounts_to_disable = {
        ctx.intermediate_ca_alias: "pki-int",
        ctx.root_ca_alias: "pki-root",
    }
    for slug, mount in mounts_to_disable.items():
        try:
            run(ctx, slug, ["secrets", "disable", mount], capture=True)
            print_ok(f"Disabled {mount} on {slug}")
        except DoerError as exc:
            print_warn(str(exc))

    if ctx.artifacts_dir.exists():
        if ctx.dry_run:
            print(f"  Would delete {ctx.artifacts_dir}")
        else:
            shutil.rmtree(ctx.artifacts_dir)
            print_ok(f"Deleted {ctx.artifacts_dir.name}/")

    if ctx.cert_root.exists():
        if ctx.dry_run:
            print(f"  Would delete {ctx.cert_root}")
        else:
            shutil.rmtree(ctx.cert_root)
            print_ok(f"Deleted {ctx.cert_root.name}/")


def rebuild_pki(ctx: Context) -> None:
    ensure_directories(ctx)
    assert_https_ready(ctx, ctx.root_ca_alias)
    if ctx.intermediate_tls:
        assert_https_ready(ctx, ctx.intermediate_ca_alias)

    print_step("Phase 1: enable/tune PKI mounts")
    _try_enable_pki(ctx, ctx.root_ca_alias, "pki-root", "87600h")
    _try_enable_pki(ctx, ctx.intermediate_ca_alias, "pki-int", "43800h")

    print_step("Phase 2: ensure root CA exists")
    write_json_output(
        ctx,
        ctx.root_ca_alias,
        ["write", "-format=json", "pki-root/root/generate/internal", 'common_name=Caedist Root CA', "ttl=87600h"],
        ctx.artifacts_dir / "root-generate.json",
    )
    root_cert_dir = ctx.cert_root / ctx.root_ca_alias
    root_cert_dir.mkdir(parents=True, exist_ok=True)
    extract_field(ctx, ctx.artifacts_dir / "root-generate.json", "certificate", root_cert_dir / "ca.pem")
    print_ok("Generated or refreshed root CA material")

    print_step("Phase 3: generate intermediate CSR")
    write_json_output(
        ctx,
        ctx.intermediate_ca_alias,
        ["write", "-format=json", "pki-int/intermediate/generate/internal", 'common_name=Caedist Intermediate CA', "ttl=43800h"],
        ctx.artifacts_dir / "intermediate.json",
    )
    extract_field(ctx, ctx.artifacts_dir / "intermediate.json", "csr", ctx.artifacts_dir / "pki-int.csr")
    print_ok("Wrote intermediate.json and pki-int.csr")

    print_step("Phase 4: sign intermediate CSR on root")
    write_json_output(
        ctx,
        ctx.root_ca_alias,
        ["write", "-format=json", "pki-root/root/sign-intermediate", f"csr=@{ctx.artifacts_dir / 'pki-int.csr'}", "format=pem_bundle", "ttl=43800h"],
        ctx.artifacts_dir / "signed-intermediate.json",
    )
    int_cert_dir = ctx.cert_root / ctx.intermediate_ca_alias
    int_cert_dir.mkdir(parents=True, exist_ok=True)
    extract_field(ctx, ctx.artifacts_dir / "signed-intermediate.json", "certificate", int_cert_dir / "ca.pem")
    print_ok("Wrote signed-intermediate.json and ca.pem")

    print_step("Phase 5: import intermediate certificate")
    run(ctx, ctx.intermediate_ca_alias, ["write", "pki-int/intermediate/set-signed", f"certificate=@{int_cert_dir / 'ca.pem'}"])
    print_ok("Imported signed intermediate certificate")

    print_step("Phase 6: configure issuing URLs")
    run(
        ctx,
        ctx.root_ca_alias,
        [
            "write",
            "pki-root/config/urls",
            f"issuing_certificates={endpoint_addr(ctx, ctx.root_ca_alias)}/v1/pki-root/ca",
            f"crl_distribution_points={endpoint_addr(ctx, ctx.root_ca_alias)}/v1/pki-root/crl",
        ],
    )
    run(
        ctx,
        ctx.intermediate_ca_alias,
        [
            "write",
            "pki-int/config/urls",
            f"issuing_certificates={endpoint_addr(ctx, ctx.intermediate_ca_alias)}/v1/pki-int/ca",
            f"crl_distribution_points={endpoint_addr(ctx, ctx.intermediate_ca_alias)}/v1/pki-int/crl",
        ],
    )
    print_ok("Configured PKI URLs")

    print_step("Phase 7: create roles")
    # Create roles on root for itself and the intermediate
    for slug in [ctx.root_ca_alias, ctx.intermediate_ca_alias]:
        run(ctx, ctx.root_ca_alias, ["write", f"pki-root/roles/{slug}-listener", "allow_any_name=true", "allow_ip_sans=true", "allow_localhost=true", "server_flag=true", "client_flag=false", 'max_ttl=8760h'])

    # Create roles on intermediate for all leaf vaults
    leaf_slugs = [slug for slug, vault in ctx.topology.items() if vault.role == 'leaf']
    for slug in leaf_slugs:
        run(ctx, ctx.intermediate_ca_alias, ["write", f"pki-int/roles/{slug}-listener", "allow_any_name=true", "allow_ip_sans=true", "allow_localhost=true", "server_flag=true", "client_flag=false", 'max_ttl=8760h'])

    print_ok("Created listener roles")

    print_step("Phase 8: issue listener certificates")
    _issue_cert(ctx, ctx.root_ca_alias, ctx.root_ca_alias, f"pki-root/issue/{ctx.root_ca_alias}-listener")
    _issue_cert(ctx, ctx.root_ca_alias, ctx.intermediate_ca_alias, f"pki-root/issue/{ctx.intermediate_ca_alias}-listener")
    for slug in leaf_slugs:
        _issue_cert(ctx, ctx.intermediate_ca_alias, slug, f"pki-int/issue/{slug}-listener")
    print_ok("Issued listener certificates")

    print_step("Phase 9: complete")
    print_ok("PKI rebuild completed. Restart/cutover decisions remain manual by design.")


def _try_enable_pki(ctx: Context, slug: str, mount: str, ttl: str) -> None:
    try:
        run(ctx, slug, ["secrets", "enable", f"-path={mount}", "pki"], capture=True)
        print_ok(f"Enabled {mount} on {slug}")
    except DoerError as exc:
        if "path is already in use" in str(exc).lower():
            print_warn(f"{mount} already enabled on {slug}")
        else:
            raise
    run(ctx, slug, ["secrets", "tune", f"-max-lease-ttl={ttl}", mount])
    print_ok(f"Tuned {mount} on {slug}")


def _issue_cert(ctx: Context, signing_slug: str, target_slug: str, issue_path: str) -> None:
    json_path = ctx.artifacts_dir / f"{target_slug}-listener.json"
    cert_dir = ctx.cert_root / target_slug
    cert_dir.mkdir(parents=True, exist_ok=True)

    write_json_output(
        ctx,
        signing_slug,
        ["write", "-format=json", issue_path, 'common_name=127.0.0.1', 'ip_sans=127.0.0.1', 'ttl=8760h'],
        json_path,
    )
    cert_path = cert_dir / "server-cert.pem"
    key_path = cert_dir / "server-key.pem"
    ca_path = cert_dir / "ca-chain.pem"

    extract_field(ctx, json_path, "certificate", cert_path)
    extract_field(ctx, json_path, "private_key", key_path)
    extract_field(ctx, json_path, "issuing_ca", cert_path, append=True)
    extract_field(ctx, json_path, "issuing_ca", ca_path)


def verify_pki(ctx: Context) -> None:
    print_step("Verifying PKI mounts and URLs")
    for slug, path in [(ctx.root_ca_alias, "pki-root/cert/ca"), (ctx.intermediate_ca_alias, "pki-int/cert/ca")]:
        try:
            run(ctx, slug, ["read", path], capture=False)
            print_ok(f"{slug}: {path} readable")
        except DoerError as exc:
            print_fail(str(exc))

    for target in ctx.topology:
        cert_path = ctx.cert_root / target / "server-cert.pem"
        key_path = ctx.cert_root / target / "server-key.pem"
        if cert_path.exists() and key_path.exists():
            print_ok(f"Certificates present for: {target}")
        else:
            print_warn(f"Certificates missing for: {target}")


def inject_failure(ctx: Context, failure_type: str) -> None:
    print_step(f"Injecting failure: {failure_type}")
    if failure_type == "wrong-root-protocol":
        broken = replace(ctx, root_tls=not ctx.root_tls, verbose=True)
        run(broken, ctx.root_ca_alias, ["status"])
        return
    if failure_type == "wrong-intermediate-protocol":
        broken = replace(ctx, intermediate_tls=not ctx.intermediate_tls, verbose=True)
        run(broken, ctx.intermediate_ca_alias, ["status"])
        return
    if failure_type == "missing-root-cacert":
        broken = replace(ctx, root_tls=True, root_cacert=None, verbose=True)
        run(broken, ctx.root_ca_alias, ["status"])
        return
    if failure_type == "bad-root-cacert-path":
        broken = replace(ctx, root_tls=True, root_cacert=ctx.artifacts_dir / "definitely-not-a-ca.pem", verbose=True)
        run(broken, ctx.root_ca_alias, ["status"])
        return
    if failure_type == "bad-intermediate-role-name":
        run(ctx, ctx.intermediate_ca_alias, ["write", "pki-int/issue/not-a-real-role", 'common_name=127.0.0.1'])
        return
    raise DoerError(f"Unsupported failure type: {failure_type}")


def main() -> int:
    args = parse_args()

    if args.command in ("rebuild-pki", "teardown-pki", "verify-pki"):
        if not args.vault_def or not args.root_ca_alias or not args.intermediate_ca_alias:
            raise DoerError("Commands rebuild-pki, teardown-pki, and verify-pki require --vault-def, --root-ca-alias, and --intermediate-ca-alias.")

    topology = {}
    if args.vault_def:
        for v_def in args.vault_def:
            try:
                slug, host, port, role = v_def.split(':')
                topology[slug] = VaultEndpoint(slug, host, int(port), role)
            except ValueError:
                raise DoerError(f"Invalid --vault-def format: {v_def}")
    ctx = build_context(args, topology)
    try:
        if args.command == "plan-rebuild":
            plan_rebuild(ctx)
        elif args.command == "teardown-pki":
            teardown_pki(ctx)
        elif args.command == "rebuild-pki":
            rebuild_pki(ctx)
        elif args.command == "verify-pki":
            verify_pki(ctx)
        elif args.command == "inject-failure":
            inject_failure(ctx, args.failure_type)
        else:
            raise DoerError(f"Unsupported command: {args.command}")
        return 0
    except DoerError as exc:
        print_fail(str(exc))
        return 1
    except KeyboardInterrupt:
        print_warn("Interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())