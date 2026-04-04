import json
import os
import re
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

from caedist_runner import (
    AssignNode,
    BlockNode,
    CaedistEvaluator,
    CaedistInterpreter,
    CaedistLexer,
    CaedistParser,
    CollectionDefNode,
    CollectionOpNode,
    ForeachNode,
    GenericNode,
    TokenType,
    TransformNode,
)


def covers(*requirement_ids):
    def decorator(func):
        func.requirement_ids = tuple(requirement_ids)
        return func

    return decorator


class LexerTests(unittest.TestCase):
    @covers("REQ-001")
    def test_tokenize_ignores_comments_and_tracks_symbols(self):
        source = """
        ; full line comment
        @Single_vault_root = "/tmp/vaults"
        system().save_to_ram[]
        transform(*system -> tls_enabled)
        """

        lexer = CaedistLexer(source)
        token_types = [token.type for token in lexer.tokens]

        self.assertIn(TokenType.AT, token_types)
        self.assertIn(TokenType.LBRACKET, token_types)
        self.assertIn(TokenType.RBRACKET, token_types)
        self.assertIn(TokenType.ARROW, token_types)
        self.assertEqual(lexer.tokens[-1].type, TokenType.EOF)


class ParserTests(unittest.TestCase):
    @covers("REQ-001")
    def test_parse_script_builds_expected_nodes(self):
        source = """
        @Single_vault_root = "/vault-root"
        secure_storage = "file"
        default_vaults = {
            "system","8900","system-vault"
            "system-unsealer","8930","system-unsealer"
        }
        default_vaults().save_to_ram[]
        transform(*system -> tls_enabled)
        """

        parser = CaedistParser(CaedistLexer(source).tokens)
        ast = parser.parse()

        self.assertEqual(len(ast.statements), 5)
        self.assertIsInstance(ast.statements[0], AssignNode)
        self.assertIsInstance(ast.statements[2], CollectionDefNode)
        self.assertIsInstance(ast.statements[3], CollectionOpNode)
        self.assertTrue(ast.statements[3].has_brackets)
        self.assertIsInstance(ast.statements[4], TransformNode)
        self.assertEqual(ast.statements[4].state, "tls_enabled")

    @covers("REQ-001")
    def test_parse_targeted_method_allows_zero_arg_method(self):
        source = "unsealer_subscriber(*system).migrate"

        parser = CaedistParser(CaedistLexer(source).tokens)
        ast = parser.parse()
        node = ast.statements[0]

        self.assertEqual(node.role, "unsealer_subscriber")
        self.assertEqual(node.target, "system")
        self.assertEqual(node.method, "migrate")
        self.assertIsNone(node.arg)


class EvaluatorTests(unittest.TestCase):
    def make_evaluator_with_vault(self, alias="system", port="8900", path_name="system-vault"):
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())
        evaluator.collections["default_vaults"] = [{"alias": alias, "port": port, "path": path_name}]
        return evaluator, evaluator.collections["default_vaults"][0]

    @covers("REQ-002")
    def test_collection_definition_groups_elements_into_triplets(self):
        node = CollectionDefNode(
            "default_vaults",
            ["system", "8900", "system-vault", "system-unsealer", "8930", "system-unsealer"],
        )
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())

        evaluator.visit(node)

        self.assertEqual(
            evaluator.collections["default_vaults"],
            [
                {"alias": "system", "port": "8900", "path": "system-vault"},
                {"alias": "system-unsealer", "port": "8930", "path": "system-unsealer"},
            ],
        )

    @covers("REQ-003")
    def test_deploy_writes_expected_vault_hcl(self):
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())
        vault = {"alias": "system", "port": "8900", "path": "system-vault"}
        tmpdir = make_workspace_tempdir()
        try:
            evaluator.globals["Single_vault_root"] = str(tmpdir)

            evaluator.execute_collection_method("default_vaults", [vault], "deploy")

            hcl_path = tmpdir / "system-vault" / "vault.hcl"
            self.assertTrue(hcl_path.exists())
            content = hcl_path.read_text()
            self.assertIn('address     = "127.0.0.1:8900"', content)
            self.assertIn('tls_disable = "true"', content)
            self.assertIn('api_addr = "http://127.0.0.1:8900"', content)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @covers("REQ-007")
    def test_transform_tls_enabled_updates_state_and_env_uses_https(self):
        evaluator, _ = self.make_evaluator_with_vault()

        evaluator.execute_transform("system", "tls_enabled")
        vault_info = evaluator.collections["default_vaults"][0]
        env = evaluator._prepare_vault_env(vault_info)

        self.assertTrue(vault_info["tls"])
        self.assertEqual(env["VAULT_ADDR"], "https://127.0.0.1:8900")

    @covers("REQ-003")
    @patch("caedist_runner.subprocess.run")
    def test_init_captures_credentials_from_vault_json(self, mock_run):
        evaluator, vault = self.make_evaluator_with_vault()
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"unseal_keys_b64":["k1","k2","k3","k4","k5"],"root_token":"root-token"}',
            stderr="",
        )

        evaluator.execute_collection_method("default_vaults", [vault], "init")

        self.assertEqual(evaluator.ram_credentials["system"]["root_token"], "root-token")
        mock_run.assert_called_once_with(
            ["vault", "operator", "init", "-format=json"],
            env=ANY,
            capture_output=True,
            text=True,
        )

    @covers("REQ-003")
    @patch("caedist_runner.subprocess.run")
    def test_unseal_uses_first_three_keys(self, mock_run):
        evaluator, vault = self.make_evaluator_with_vault()
        evaluator.ram_credentials["system"] = {
            "unseal_keys_b64": ["k1", "k2", "k3", "k4", "k5"],
            "root_token": "root-token",
        }
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        evaluator.execute_collection_method("default_vaults", [vault], "unseal")

        self.assertEqual(mock_run.call_count, 3)
        self.assertEqual(mock_run.call_args_list[0].args[0], ["vault", "operator", "unseal", "k1"])
        self.assertEqual(mock_run.call_args_list[1].args[0], ["vault", "operator", "unseal", "k2"])
        self.assertEqual(mock_run.call_args_list[2].args[0], ["vault", "operator", "unseal", "k3"])

    @covers("REQ-003")
    @patch("caedist_runner.subprocess.run")
    def test_login_uses_root_token(self, mock_run):
        evaluator, vault = self.make_evaluator_with_vault()
        evaluator.ram_credentials["system"] = {"root_token": "root-token"}
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        evaluator.execute_collection_method("default_vaults", [vault], "login")

        mock_run.assert_called_once_with(
            ["vault", "login", "root-token"],
            env=ANY,
            capture_output=True,
            text=True,
        )

    @covers("REQ-003")
    @patch("caedist_runner.subprocess.run")
    def test_status_parses_json_response(self, mock_run):
        evaluator, vault = self.make_evaluator_with_vault()
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"sealed":false,"version":"1.16.0","cluster_name":"vault-cluster"}',
            stderr="",
        )

        evaluator.execute_collection_method("default_vaults", [vault], "status")

        mock_run.assert_called_once_with(
            ["vault", "status", "-format=json"],
            env=ANY,
            capture_output=True,
            text=True,
            timeout=5,
        )

    @covers("REQ-004")
    def test_savecreds_file_writes_expected_init_keys_json(self):
        evaluator, vault = self.make_evaluator_with_vault()
        evaluator.secure_storage_config["mode"] = "file"
        evaluator.ram_credentials["system"] = {
            "unseal_keys_b64": ["k1", "k2", "k3", "k4", "k5"],
            "root_token": "root-token",
        }
        tmpdir = make_workspace_tempdir()
        try:
            evaluator.globals["Single_vault_root"] = str(tmpdir)
            (tmpdir / vault["path"]).mkdir(parents=True, exist_ok=True)

            evaluator.execute_collection_method("default_vaults", [vault], "savecreds")

            saved = json.loads((tmpdir / vault["path"] / "init_keys.json").read_text())
            self.assertEqual(saved["key1"], "k1")
            self.assertEqual(saved["key5"], "k5")
            self.assertEqual(saved["root"], "root-token")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @covers("REQ-004")
    @patch.dict(os.environ, {}, clear=True)
    @patch("caedist_runner.getpass.getpass", return_value="prompted-token")
    @patch("caedist_runner.subprocess.run")
    def test_savecreds_vault_prompts_for_token_and_writes_kv_payload(self, mock_run, mock_getpass):
        evaluator, vault = self.make_evaluator_with_vault()
        evaluator.secure_storage_config["mode"] = "vault"
        evaluator.secure_storage_config["payload"] = "http://127.0.0.1:9500"
        evaluator.ram_credentials["system"] = {
            "unseal_keys_b64": ["k1", "k2", "k3", "k4", "k5"],
            "root_token": "root-token",
        }
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        evaluator.execute_collection_method("default_vaults", [vault], "savecreds")

        mock_getpass.assert_called_once()
        self.assertEqual(mock_run.call_args.args[0], ["vault", "write", "kv/data/system", "-"])
        self.assertEqual(mock_run.call_args.kwargs["env"]["VAULT_ADDR"], "http://127.0.0.1:9500")
        self.assertEqual(mock_run.call_args.kwargs["env"]["VAULT_TOKEN"], "prompted-token")
        payload = json.loads(mock_run.call_args.kwargs["input"])
        self.assertEqual(payload["data"]["root"], "root-token")

    @covers("REQ-005")
    def test_foreach_binds_aliases_into_loop_body(self):
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())
        evaluator.collections["default_vaults"] = [
            {"alias": "system", "port": "8900", "path": "system-vault"},
            {"alias": "user", "port": "8800", "path": "user-vault"},
        ]
        loop = ForeachNode("vault_alias", "default_vaults", BlockNode([GenericNode({"Function": "emit_to_screen", "arg": "loop"})]))

        with patch.object(evaluator, "visit_block", wraps=evaluator.visit_block) as wrapped_visit_block:
            evaluator.visit(loop)

        self.assertEqual(wrapped_visit_block.call_count, 2)
        self.assertEqual(evaluator.locals["vault_alias"], "user")

    @covers("REQ-005")
    @patch("caedist_runner.terminal_launcher.spawn_terminal")
    def test_spawn_terminal_resolves_target_from_loop_variable(self, mock_spawn_terminal):
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())
        evaluator.globals["Single_vault_root"] = "C:/vault-root"
        evaluator.locals["loop_var"] = "system"
        evaluator.collections["default_vaults"] = [{"alias": "system", "port": "8900", "path": "system-vault"}]
        node = GenericNode({"Function": "spawn_terminal", "target": "loop_var"})

        evaluator.visit(node)

        mock_spawn_terminal.assert_called_once()
        self.assertEqual(mock_spawn_terminal.call_args.args[:3], ("system", "8900", "system-vault"))

    @covers("REQ-006", "REQ-010")
    @patch("caedist_runner.subprocess.run")
    def test_add_role_unsealer_enables_transit_and_creates_key(self, mock_run):
        evaluator, _ = self.make_evaluator_with_vault(alias="system-unsealer", port="8930", path_name="system-unsealer")
        evaluator.ram_credentials["system-unsealer"] = {"root_token": "root-token"}
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]

        evaluator.execute_targeted_op("add_role", "unsealer", "system-unsealer")

        self.assertEqual(mock_run.call_args_list[0].args[0], ["vault", "secrets", "enable", "transit"])
        self.assertEqual(mock_run.call_args_list[1].args[0], ["vault", "write", "-f", "transit/keys/autounseal"])
        self.assertEqual(mock_run.call_args_list[0].kwargs["env"]["VAULT_TOKEN"], "root-token")

    @covers("REQ-006")
    @patch("caedist_runner.subprocess.run")
    def test_subscribe_to_writes_policy_creates_token_and_appends_seal_block(self, mock_run):
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())
        evaluator.collections["default_vaults"] = [
            {"alias": "system", "port": "8900", "path": "system-vault"},
            {"alias": "system-unsealer", "port": "8930", "path": "system-unsealer"},
        ]
        evaluator.ram_credentials["system-unsealer"] = {"root_token": "root-token"}

        tmpdir = make_workspace_tempdir()
        try:
            evaluator.globals["Single_vault_root"] = str(tmpdir)
            subscriber_dir = tmpdir / "system-vault"
            unsealer_dir = tmpdir / "system-unsealer"
            subscriber_dir.mkdir(parents=True, exist_ok=True)
            unsealer_dir.mkdir(parents=True, exist_ok=True)
            (subscriber_dir / "vault.hcl").write_text('listener "tcp" {\n  address = "127.0.0.1:8900"\n}\n')

            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=0, stdout='{"auth":{"client_token":"periodic-token"}}', stderr=""),
            ]

            evaluator.execute_targeted_method("unsealer_subscriber", "system", "subscribeTo", "system-unsealer")

            policy_write = mock_run.call_args_list[0]
            token_create = mock_run.call_args_list[1]

            self.assertEqual(policy_write.args[0][:3], ["vault", "policy", "write"])
            self.assertEqual(token_create.args[0][:3], ["vault", "token", "create"])
            self.assertTrue((unsealer_dir / "autounseal-system.hcl").exists())
            subscriber_hcl = (subscriber_dir / "vault.hcl").read_text()
            self.assertIn('seal "transit"', subscriber_hcl)
            self.assertIn('token = "periodic-token"', subscriber_hcl)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @covers("REQ-006")
    @patch("caedist_runner.subprocess.run")
    def test_migrate_uses_migrate_flag_with_first_three_keys(self, mock_run):
        evaluator, _ = self.make_evaluator_with_vault()
        evaluator.ram_credentials["system"] = {"unseal_keys_b64": ["k1", "k2", "k3", "k4", "k5"]}
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        evaluator.execute_targeted_method("unsealer_subscriber", "system", "migrate", None)

        self.assertEqual(mock_run.call_count, 3)
        self.assertEqual(mock_run.call_args_list[0].args[0], ["vault", "operator", "unseal", "-migrate", "k1"])
        self.assertEqual(mock_run.call_args_list[2].args[0], ["vault", "operator", "unseal", "-migrate", "k3"])

    @covers("REQ-007")
    def test_tls_enable_rewrites_listener_and_api_addr(self):
        evaluator, vault = self.make_evaluator_with_vault()
        tmpdir = make_workspace_tempdir()
        try:
            evaluator.globals["Single_vault_root"] = str(tmpdir)
            vault_dir = tmpdir / vault["path"]
            cert_dir = tmpdir / "certstore" / vault["alias"]
            vault_dir.mkdir(parents=True, exist_ok=True)
            cert_dir.mkdir(parents=True, exist_ok=True)
            (vault_dir / "vault.hcl").write_text(
                'listener "tcp" {\n'
                '  address     = "127.0.0.1:8900"\n'
                '  tls_disable = "true"\n'
                '}\n\n'
                'api_addr = "http://127.0.0.1:8900"\n'
            )

            evaluator.execute_vault_command("tls_enable", "system")

            hcl = (vault_dir / "vault.hcl").read_text()
            self.assertIn('tls_disable = "false"', hcl)
            self.assertIn('tls_cert_file = "', hcl)
            self.assertIn('tls_key_file = "', hcl)
            self.assertIn('api_addr = "https://127.0.0.1:8900"', hcl)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @covers("REQ-007", "REQ-010")
    @patch("caedist_runner.subprocess.Popen")
    def test_targeted_start_ignores_undeclared_alias(self, mock_popen):
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())

        evaluator.execute_vault_command("start", "missing")

        mock_popen.assert_not_called()

    @covers("REQ-008")
    @patch("caedist_runner.subprocess.run")
    def test_pki_build_constructs_expected_command(self, mock_run):
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())
        evaluator.collections["default_vaults"] = [
            {"alias": "root", "port": "8900", "path": "root-vault"},
            {"alias": "intermediate", "port": "8910", "path": "intermediate-vault"},
            {"alias": "leaf", "port": "8920", "path": "leaf-vault"},
        ]
        evaluator.ram_credentials["root"] = {"root_token": "root-token"}
        evaluator.ram_credentials["intermediate"] = {"root_token": "intermediate-token"}
        evaluator.globals["Single_vault_root"] = "C:/vault-root"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        evaluator.execute_pki_build(type("Node", (), {"root_alias": "root", "intermediate_alias": "intermediate"})())

        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd[:3], [sys.executable, "vault_pki_doer.py", "rebuild-pki"])
        self.assertIn("--root-ca-token", cmd)
        self.assertIn("root-token", cmd)
        self.assertIn("--intermediate-ca-token", cmd)
        self.assertIn("intermediate-token", cmd)
        self.assertIn("root:127.0.0.1:8900:root_ca", cmd)
        self.assertIn("intermediate:127.0.0.1:8910:intermediate_ca", cmd)
        self.assertIn("leaf:127.0.0.1:8920:leaf", cmd)
        self.assertIn("--vault-root", cmd)
        self.assertIn("C:/vault-root", cmd)
        self.assertIn("--cert-root", cmd)
        self.assertIn(str(Path("C:/vault-root") / "certstore"), cmd)
        self.assertIn("--artifacts-dir", cmd)
        self.assertIn(str(Path("C:/vault-root") / "pki-artifacts"), cmd)

    @covers("REQ-010")
    @patch("caedist_runner.subprocess.run")
    def test_undefined_targeted_op_does_not_invoke_subprocess(self, mock_run):
        evaluator = CaedistEvaluator(type("FakeAst", (), {"statements": []})())

        evaluator.execute_targeted_op("add_role", "unsealer", "missing")

        mock_run.assert_not_called()


class InterpreterTests(unittest.TestCase):
    @covers("REQ-001")
    def test_interpreter_caches_ast_between_calls(self):
        source = 'secure_storage = "nosave"'
        tmpdir = make_workspace_tempdir()
        try:
            script_path = tmpdir / "sample.caedist"
            script_path.write_text(source)

            interpreter = CaedistInterpreter(str(script_path))
            first_ast = interpreter._get_ast()
            second_ast = interpreter._get_ast()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        self.assertIs(first_ast, second_ast)

    @covers("REQ-009")
    def test_warm_start_script_parses_and_contains_start_then_status(self):
        script_path = Path(__file__).resolve().parents[1] / "warm-start.caedist"
        interpreter = CaedistInterpreter(str(script_path))

        ast = interpreter._get_ast()
        collection_ops = [stmt for stmt in ast.statements if isinstance(stmt, CollectionOpNode)]

        self.assertGreaterEqual(len(collection_ops), 2)
        self.assertEqual(collection_ops[0].method, "start")
        self.assertEqual(collection_ops[1].method, "status")


class RequirementsTraceabilityTests(unittest.TestCase):
    @covers("REQ-001", "REQ-002", "REQ-003", "REQ-004", "REQ-005", "REQ-006", "REQ-007", "REQ-008", "REQ-009", "REQ-010")
    def test_all_good_confidence_requirements_have_mapped_tests(self):
        requirements_path = Path(__file__).resolve().parents[1] / "REQUIREMENTS.md"
        requirements_text = requirements_path.read_text(encoding="utf-8")

        implemented_section = requirements_text.split("### Implemented With Good Confidence", 1)[1]
        implemented_section = implemented_section.split("### Partially Implemented Or Fragile", 1)[0]
        expected_requirement_ids = set(re.findall(r"REQ-\d{3}", implemented_section))
        declared_requirement_ids = set(re.findall(r"### (REQ-\d{3}) ", requirements_text))

        self.assertTrue(expected_requirement_ids)
        self.assertTrue(expected_requirement_ids.issubset(declared_requirement_ids))

        covered_requirement_ids = collect_test_requirement_ids()
        missing = expected_requirement_ids - covered_requirement_ids
        self.assertEqual(set(), missing, f"Missing test mappings for: {sorted(missing)}")

    def test_all_test_requirement_tags_exist_in_requirements_doc(self):
        requirements_path = Path(__file__).resolve().parents[1] / "REQUIREMENTS.md"
        declared_requirement_ids = set(re.findall(r"### (REQ-\d{3}) ", requirements_path.read_text(encoding="utf-8")))
        tagged_requirement_ids = collect_test_requirement_ids()

        self.assertTrue(tagged_requirement_ids.issubset(declared_requirement_ids))


def collect_test_requirement_ids():
    tagged_requirement_ids = set()
    loader = unittest.defaultTestLoader
    for case in (LexerTests, ParserTests, EvaluatorTests, InterpreterTests, RequirementsTraceabilityTests):
        for name in loader.getTestCaseNames(case):
            method = getattr(case, name)
            tagged_requirement_ids.update(getattr(method, "requirement_ids", ()))
    return tagged_requirement_ids


def make_workspace_tempdir() -> Path:
    root = Path(__file__).resolve().parents[1] / ".test-artifacts"
    path = root / str(uuid.uuid4())
    path.mkdir(parents=True, exist_ok=False)
    return path


if __name__ == "__main__":
    unittest.main(verbosity=2)
