#!/usr/bin/env python3
import re
import json
import enum
import argparse
import subprocess
import os
import time
import getpass
from pathlib import Path
import terminal_launcher

class TokenType(enum.Enum):
    # Symbols
    AT = "@"
    ASSIGN = "="
    LBRACE = "{"
    RBRACE = "}"
    LPAREN = "("
    RPAREN = ")"
    LBRACKET = "["
    RBRACKET = "]"
    DOT = "."
    COMMA = ","
    COLON = ":"
    STAR = "*"
    ARROW = "->"
    
    # Primitives
    IDENTIFIER = "IDENTIFIER"
    STRING = "STRING"
    NUMBER = "NUMBER"
    EOF = "EOF"

class Token:
    def __init__(self, type_: TokenType, value: str, line: int, column: int):
        self.type = type_
        self.value = value
        self.line = line
        self.column = column

    def __repr__(self):
        return f"Token({self.type.name}, {self.value!r}, line={self.line}, col={self.column})"

class CaedistLexer:
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.tokens = []
        self.tokenize()

    def tokenize(self):
        """Scans the source code and generates a list of tokens."""
        # Regex patterns for different token types
        rules = [
            ('STRING',     r'"[^"]*"'),
            ('NUMBER',     r'\d+'),
            ('IDENTIFIER', r'[A-Za-z_][A-Za-z0-9_-]*'),
            ('AT',         r'@'),
            ('ASSIGN',     r'='),
            ('LBRACE',     r'\{'),
            ('RBRACE',     r'\}'),
            ('LPAREN',     r'\('),
            ('RPAREN',     r'\)'),
            ('LBRACKET',   r'\['),
            ('RBRACKET',   r'\]'),
            ('DOT',        r'\.'),
            ('ARROW',      r'->'),
            ('COMMA',      r','),
            ('COLON',      r':'),
            ('STAR',       r'\*'),
            ('COMMENT',    r'[;#].*'),       # Ignore comments starting with ; or #
            ('NEWLINE',    r'\n'),           # Track line numbers
            ('SKIP',       r'[ \t]+'),       # Ignore spaces and tabs
            ('MISMATCH',   r'.'),            # Any other character is an error
        ]
        
        # Combine all regex rules into one massive pattern using named capture groups
        tok_regex = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in rules)
        
        line_num = 1
        line_start = 0
        
        for mo in re.finditer(tok_regex, self.source_code):
            kind = mo.lastgroup
            value = mo.group()
            column = mo.start() - line_start
            
            if kind == 'STRING':
                self.tokens.append(Token(TokenType.STRING, value.strip('"'), line_num, column))
            elif kind == 'NUMBER':
                self.tokens.append(Token(TokenType.NUMBER, int(value), line_num, column))
            elif kind == 'IDENTIFIER':
                self.tokens.append(Token(TokenType.IDENTIFIER, value, line_num, column))
            elif kind in [t.name for t in TokenType]:
                # Matches exactly one of our symbol TokenTypes
                self.tokens.append(Token(TokenType[kind], value, line_num, column))
            elif kind == 'NEWLINE':
                line_num += 1
                line_start = mo.end()
            elif kind in ('SKIP', 'COMMENT'):
                continue
            elif kind == 'MISMATCH':
                raise RuntimeError(f'Unexpected character {value!r} on line {line_num}, col {column}')
                
        self.tokens.append(Token(TokenType.EOF, '', line_num, 0))

class ASTNode:
    def to_dict(self):
        raise NotImplementedError()

    def __repr__(self):
        return json.dumps(self.to_dict(), indent=2)

class BlockNode(ASTNode):
    def __init__(self, statements):
        self.statements = statements
    def to_dict(self):
        return [s.to_dict() for s in self.statements if s]

class AssignNode(ASTNode):
    def __init__(self, name, value, is_global=False):
        self.name = name
        self.value = value
        self.is_global = is_global
    def to_dict(self):
        return {"Assign": {"name": self.name, "value": self.value, "is_global": self.is_global}}

class CollectionDefNode(ASTNode):
    def __init__(self, name, elements):
        self.name = name
        self.elements = elements
    def to_dict(self):
        return {"CollectionDef": {"name": self.name, "elements": self.elements}}

class CollectionOpNode(ASTNode):
    def __init__(self, collection, method, has_brackets=False):
        self.collection = collection
        self.method = method
        self.has_brackets = has_brackets
    def to_dict(self):
        return {"CollectionOp": {"collection": self.collection, "method": self.method, "brackets": self.has_brackets}}

class TargetedOpNode(ASTNode):
    def __init__(self, action, role, target):
        self.action = action
        self.role = role
        self.target = target
    def to_dict(self):
        return {"TargetedOp": {"action": self.action, "role": self.role, "target": self.target}}

class TargetedMethodNode(ASTNode):
    def __init__(self, role, target, method, arg):
        self.role = role
        self.target = target
        self.method = method
        self.arg = arg
    def to_dict(self):
        return {"TargetedMethod": {"role": self.role, "target": self.target, "method": self.method, "arg": self.arg}}

class VaultCommandNode(ASTNode):
    def __init__(self, command, target):
        self.command = command
        self.target = target
    def to_dict(self):
        return {"VaultCommand": {"command": self.command, "target": self.target}}

class PKIBuildNode(ASTNode):
    def __init__(self, root_alias, intermediate_alias):
        self.root_alias = root_alias
        self.intermediate_alias = intermediate_alias
    def to_dict(self):
        return {"PKIBuild": {"root": self.root_alias, "intermediate": self.intermediate_alias}}

class TransformNode(ASTNode):
    def __init__(self, target, state):
        self.target = target
        self.state = state
    def to_dict(self):
        return {"Transform": {"target": self.target, "state": self.state}}

class GenericNode(ASTNode):
    def __init__(self, data):
        self.data = data
    def to_dict(self):
        return self.data

class SwitchNode(ASTNode):
    def __init__(self, condition, cases, default_case):
        self.condition = condition
        self.cases = cases
        self.default_case = default_case
    def to_dict(self):
        return {
            "Switch": {
                "condition": self.condition,
                "cases": [c.to_dict() for c in self.cases],
                "default": self.default_case.to_dict() if self.default_case else None
            }
        }

class CaseNode(ASTNode):
    def __init__(self, value, body):
        self.value = value
        self.body = body
    def to_dict(self):
        return {"Case": {"value": self.value, "body": self.body.to_dict() if self.body else []}}

class ForeachNode(ASTNode):
    def __init__(self, var, collection, body):
        self.var = var
        self.collection = collection
        self.body = body
    def to_dict(self):
        return {"Foreach": {"var": self.var, "collection": self.collection, "body": self.body.to_dict() if self.body else []}}

class CaedistParser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def current(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]

    def peek(self, offset=1):
        if self.pos + offset < len(self.tokens):
            return self.tokens[self.pos + offset]
        return self.tokens[-1]

    def advance(self):
        self.pos += 1
        return self.current()

    def consume(self, expected_type):
        token = self.current()
        if token.type == expected_type:
            self.advance()
            return token
        raise SyntaxError(f"Expected {expected_type.name} at line {token.line}, col {token.column}, got {token.type.name} ('{token.value}')")

    def parse(self):
        return self.parse_block(TokenType.EOF)

    def parse_block(self, end_token_type=TokenType.RBRACE):
        """Parses a sequence of statements until a specific end token is hit."""
        statements = []
        while self.current().type not in (end_token_type, TokenType.EOF):
            stmt = self.parse_statement()
            if stmt:
                statements.append(stmt)
                
        if self.current().type == end_token_type and end_token_type != TokenType.EOF:
            self.advance() # Consume the closing token
            
        return BlockNode(statements)

    def parse_statement(self):
        token = self.current()

        if token.type == TokenType.AT:
            return self.parse_global_assign()

        if token.type == TokenType.IDENTIFIER:
            # Check for keyword-based statements FIRST to avoid ambiguity with structural patterns
            if token.value == "switch":
                return self.parse_switch()
            elif token.value == "foreach":
                return self.parse_foreach()
            elif token.value == "emit_to_screen":
                return self.parse_emit()
            elif token.value == "spawn_terminal":
                self.consume(TokenType.IDENTIFIER)
                self.consume(TokenType.LBRACKET)
                target = self.consume(TokenType.IDENTIFIER).value
                self.consume(TokenType.RBRACKET)
                return GenericNode({"Function": "spawn_terminal", "target": target})
            elif token.value == "pki_build":
                return self.parse_pki_build()
            elif token.value == "transform":
                return self.parse_transform()

            # If not a keyword, check for structural patterns
            p1 = self.peek(1)
            p2 = self.peek(2)
            p3 = self.peek(3)
            p4 = self.peek(4)
            p5 = self.peek(5)

            if p1.type == TokenType.ASSIGN:
                if p2.type == TokenType.LBRACE:
                    return self.parse_collection_def()
                else:
                    return self.parse_assign()

            elif p1.type == TokenType.LPAREN and p2.type == TokenType.RPAREN and p3.type == TokenType.DOT:
                return self.parse_collection_op()

            elif p1.type == TokenType.LPAREN and p2.type == TokenType.STAR:
                if p5.type == TokenType.DOT:
                    return self.parse_targeted_method()
                else:
                    return self.parse_vault_command()

            elif p1.type == TokenType.DOT:
                return self.parse_targeted_op()

        if token.type == TokenType.RBRACE:
            self.advance()
            return None

        raise SyntaxError(f"Unexpected token {token.type.name} ('{token.value}') at line {token.line}, col {token.column}")

    def parse_global_assign(self):
        self.consume(TokenType.AT)
        name = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.ASSIGN)
        value = self.consume(TokenType.STRING).value
        return AssignNode(name, value, is_global=True)

    def parse_assign(self):
        name = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.ASSIGN)
        value = self.consume(TokenType.STRING).value
        return AssignNode(name, value, is_global=False)

    def parse_collection_def(self):
        name = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.ASSIGN)
        self.consume(TokenType.LBRACE)
        elements = []
        while self.current().type not in (TokenType.RBRACE, TokenType.EOF):
            if self.current().type in (TokenType.STRING, TokenType.NUMBER):
                elements.append(str(self.current().value))
                self.advance()
            elif self.current().type == TokenType.COMMA:
                self.advance()
            else:
                self.advance()
        self.consume(TokenType.RBRACE)
        return CollectionDefNode(name, elements)

    def parse_collection_op(self):
        collection = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.LPAREN)
        self.consume(TokenType.RPAREN)
        self.consume(TokenType.DOT)
        method = self.consume(TokenType.IDENTIFIER).value
        
        has_brackets = False
        if self.current().type == TokenType.LBRACKET:
            self.consume(TokenType.LBRACKET)
            self.consume(TokenType.RBRACKET)
            has_brackets = True
        elif self.current().type == TokenType.LPAREN:
            self.consume(TokenType.LPAREN)
            self.consume(TokenType.RPAREN)
            
        return CollectionOpNode(collection, method, has_brackets)

    def parse_targeted_op(self):
        action = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.DOT)
        role = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.LPAREN)
        self.consume(TokenType.STAR)
        target = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.RPAREN)
        return TargetedOpNode(action, role, target)

    def parse_targeted_method(self):
        role = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.LPAREN)
        self.consume(TokenType.STAR)
        target = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.RPAREN)
        
        self.consume(TokenType.DOT)
        method = self.consume(TokenType.IDENTIFIER).value
        
        arg = None
        # Argument is optional to support zero-arg targeted methods like .migrate
        if self.current().type == TokenType.LPAREN:
            self.consume(TokenType.LPAREN)
            if self.current().type == TokenType.STAR:
                self.consume(TokenType.STAR)
                arg = self.consume(TokenType.IDENTIFIER).value
            self.consume(TokenType.RPAREN)
        
        return TargetedMethodNode(role, target, method, arg)

    def parse_vault_command(self):
        command = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.LPAREN)
        self.consume(TokenType.STAR)
        target = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.RPAREN)
        return VaultCommandNode(command, target)

    def parse_pki_build(self):
        self.consume(TokenType.IDENTIFIER) # pki_build
        self.consume(TokenType.LPAREN)

        # Expects 'root: *alias, intermediate: *alias'
        self.consume(TokenType.IDENTIFIER) # root
        self.consume(TokenType.COLON)
        self.consume(TokenType.STAR)
        root_alias = self.consume(TokenType.IDENTIFIER).value

        self.consume(TokenType.COMMA)

        self.consume(TokenType.IDENTIFIER) # intermediate
        self.consume(TokenType.COLON)
        self.consume(TokenType.STAR)
        intermediate_alias = self.consume(TokenType.IDENTIFIER).value

        self.consume(TokenType.RPAREN)
        return PKIBuildNode(root_alias, intermediate_alias)

    def parse_transform(self):
        self.consume(TokenType.IDENTIFIER) # transform
        self.consume(TokenType.LPAREN)
        self.consume(TokenType.STAR)
        target = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.ARROW)
        state = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.RPAREN)
        return TransformNode(target, state)

    def parse_switch(self):
        self.advance() # consume 'switch'
        self.consume(TokenType.LPAREN)
        cond = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.RPAREN)
        self.consume(TokenType.LBRACE)
        
        cases = []
        default_case = None
        
        while self.current().type not in (TokenType.RBRACE, TokenType.EOF):
            token = self.current()
            if token.value in ("case", "default"):
                is_default = (token.value == "default")
                self.advance()
                self.consume(TokenType.COLON)
                val = self.consume(TokenType.IDENTIFIER).value

                # Enforce that every case must have a body enclosed in braces.
                self.consume(TokenType.LBRACE)
                body = self.parse_block(TokenType.RBRACE) # Re-use the robust block parser

                node = CaseNode(val, body)
                if is_default:
                    default_case = node
                else:
                    cases.append(node)
            else:
                # If it's not a case, default, or the closing brace, it's a syntax error.
                raise SyntaxError(f"Unexpected token {token.type.name} ('{token.value}') inside switch statement at line {token.line}, col {token.column}")
                
        self.consume(TokenType.RBRACE)
        return SwitchNode(cond, cases, default_case)

    def parse_foreach(self):
        self.advance() # consume 'foreach'
        var = self.consume(TokenType.IDENTIFIER).value
        if self.current().value == "in":
            self.advance()
        else:
            self.consume(TokenType.IDENTIFIER)
        coll = self.consume(TokenType.IDENTIFIER).value
        self.consume(TokenType.LBRACE)
        
        body = self.parse_block(TokenType.RBRACE)
        return ForeachNode(var, coll, body)

    def parse_emit(self):
        self.consume(TokenType.IDENTIFIER)
        self.consume(TokenType.LPAREN)
        if self.current().type == TokenType.STRING:
            val = self.consume(TokenType.STRING).value
            self.consume(TokenType.RPAREN)
            return GenericNode({"Function": "emit_to_screen", "arg": val})
        else:
            expr = None
            if self.current().type == TokenType.IDENTIFIER:
                p1 = self.peek(1)
                p2 = self.peek(2)
                p3 = self.peek(3)
                if p1.type == TokenType.LPAREN and p2.type == TokenType.RPAREN and p3.type == TokenType.DOT:
                    expr = self.parse_collection_op()
            self.consume(TokenType.RPAREN)
            return GenericNode({"Function": "emit_to_screen", "arg": expr.to_dict() if expr else None})

class CaedistEvaluator:
    def __init__(self, ast: BlockNode):
        self.ast = ast
        self.globals = {}
        self.locals = {}
        self.collections = {}
        self.processes = []
        self.ram_credentials = {}
        self.secure_storage_config = {"mode": None, "payload": None}

    def evaluate(self):
        print("\n--- Execution Engine Starting ---")
        print("Walking the Abstract Syntax Tree...")
        self.visit_block(self.ast)
        
        print("\n--- Execution Engine State ---")
        
        print("Final State of Global Variables (@):")
        if not self.globals:
            print("  (None)")
        else:
            for key, value in self.globals.items():
                print(f'  - @{key} = "{value}"')

        print("\nFinal State of Local Variables:")
        if not self.locals:
            print("  (None)")
        else:
            for key, value in self.locals.items():
                print(f'  - {key} = "{value}"')

        print("\nFinal State of Collections:")
        if not self.collections:
            print("  (None)")
        else:
            for name, coll in self.collections.items():
                print(f"  Collection '{name}' ({len(coll)} members):")
                for vault in coll:
                    print(f"    - Alias: {vault['alias']}, Port: {vault['port']}, Path: {vault['path']}")
                    
        print("\n--- Execution Complete ---")

    def visit_block(self, block: BlockNode):
        for stmt in block.statements:
            self.visit(stmt)

    def visit(self, node: ASTNode):
        if isinstance(node, AssignNode):
            if node.is_global:
                self.globals[node.name] = node.value
            else:
                self.locals[node.name] = node.value
            print(f"[State] Set {node.name} = '{node.value}'")
            
        elif isinstance(node, CollectionDefNode):
            vaults = []
            # Group the flat elements list into triplets (alias, port, path)
            it = iter(node.elements)
            for alias in it:
                try:
                    port = next(it)
                    path = next(it)
                    vaults.append({"alias": alias, "port": port, "path": path})
                except StopIteration:
                    break
            self.collections[node.name] = vaults
            print(f"[State] Loaded collection '{node.name}' with {len(vaults)} vaults.")
            
        elif isinstance(node, CollectionOpNode):
            if node.collection not in self.collections:
                print(f"[Skipping] Cannot operate on undefined collection: {node.collection}")
            else:
                self.execute_collection_method(node.collection, self.collections[node.collection], node.method)
                
        elif isinstance(node, SwitchNode):
            cond_val_str = str(self.locals.get(node.condition, self.globals.get(node.condition, "")))
            
            # Parse the secure_storage setting per DESIGN.md#4
            parts = cond_val_str.split('=', 1)
            mode = parts[0]
            payload = parts[1] if len(parts) > 1 else None
            
            self.secure_storage_config['mode'] = mode
            self.secure_storage_config['payload'] = payload
            
            print(f"[Control] Evaluating switch on '{node.condition}' (mode: '{mode}', payload: '{payload}')")
            
            matched = False
            for case_node in node.cases:
                if case_node.value == mode: # Exact match on the mode
                    print(f"  -> Matched case: '{case_node.value}'")
                    self.visit_block(case_node.body)
                    matched = True
                    break
                    
            if not matched and node.default_case:
                print("  -> Matched default case")
                self.visit_block(node.default_case.body)
                
        elif isinstance(node, ForeachNode):
            collection = self.collections.get(node.collection, [])
            for item in collection:
                self.locals[node.var] = item['alias']
                self.visit_block(node.body)
                
        elif isinstance(node, GenericNode):
            func = node.data.get("Function")
            if func == "emit_to_screen":
                arg = node.data.get("arg")
                if isinstance(arg, dict) and "CollectionOp" in arg:
                    print(f"[Screen] >>> Credentials currently in RAM: {list(self.ram_credentials.keys())} <<<")
                else:
                    clean_arg = str(arg).replace('\\r\\n', '\n')
                    print(f"[Screen] >>> {clean_arg} <<<")
            elif func == "spawn_terminal":
                target_var = node.data.get("target")
                # Resolve variable (e.g. from foreach loop) or treat as raw string
                target_alias = self.locals.get(target_var, target_var)
                
                vault_info = None
                for coll in self.collections.values():
                    for v in coll:
                        if v['alias'] == target_alias:
                            vault_info = v
                            break
                    if vault_info:
                        break
                
                if vault_info:
                    print(f"  -> [Action] Spawning interactive terminal for '{target_alias}'...")
                    vault_root = Path(self.globals.get("Single_vault_root", "./")).resolve()
                    terminal_launcher.spawn_terminal(vault_info['alias'], vault_info['port'], vault_info['path'], vault_root)
                    time.sleep(0.5) # Prevent window manager race conditions
                else:
                    print(f"  -> [Error] Cannot spawn terminal: Vault '{target_alias}' not found.")
        
        elif isinstance(node, TargetedOpNode):
            target_resolved = self.locals.get(node.target, node.target)
            print(f"  -> [Action] Executing '{node.action}' on role '{node.role}' for target '{target_resolved}'...")
            self.execute_targeted_op(node.action, node.role, target_resolved)
            
        elif isinstance(node, TargetedMethodNode):
            target_resolved = self.locals.get(node.target, node.target)
            if node.arg:
                arg_resolved = self.locals.get(node.arg, node.arg)
                print(f"  -> [Action] Invoking '{node.method}({arg_resolved})' on role '{node.role}' for target '{target_resolved}'...")
            else:
                arg_resolved = None
                print(f"  -> [Action] Invoking '{node.method}()' on role '{node.role}' for target '{target_resolved}'...")
            self.execute_targeted_method(node.role, target_resolved, node.method, arg_resolved)
            
        elif isinstance(node, VaultCommandNode):
            target_resolved = self.locals.get(node.target, node.target)
            print(f"  -> [Action] Executing vault command '{node.command}' on target '{target_resolved}'...")
            self.execute_vault_command(node.command, target_resolved)
            
        elif isinstance(node, PKIBuildNode):
            self.execute_pki_build(node)
            
        elif isinstance(node, TransformNode):
            target_resolved = self.locals.get(node.target, node.target)
            self.execute_transform(target_resolved, node.state)
            
        else:
            print(f"[Skipping] Node type '{node.__class__.__name__}' is not yet implemented.")

    def execute_collection_method(self, name: str, vaults: list, method: str):
        """Executes a method on a collection of vaults."""
        print(f"[{name}] Executing .{method}()")
        if method == "deploy":
            vault_root = Path(self.globals.get("Single_vault_root", "./")).resolve()
            print(f"  -> Using vault root: {vault_root}")
            for vault in vaults:
                vault_dir = vault_root / vault['path']
                data_dir = vault_dir / "data"

                print(f"  -> Scaffolding for '{vault['alias']}' at {vault_dir}")
                
                vault_dir.mkdir(parents=True, exist_ok=True)
                data_dir.mkdir(parents=True, exist_ok=True)

                hcl_path = vault_dir / "vault.hcl"
                hcl_content = f"""listener "tcp" {{
  address     = "127.0.0.1:{vault['port']}"
  tls_disable = "true"
}}

storage "file" {{
  path = "{data_dir.resolve().as_posix()}"
}}

api_addr = "http://127.0.0.1:{vault['port']}"
ui = true
disable_mlock = true
"""
                hcl_path.write_text(hcl_content)
                print(f"     Wrote generic HCL to {hcl_path}")
        elif method == "start":
            vault_root = Path(self.globals.get("Single_vault_root", "./")).resolve()
            env = os.environ.copy()
            for vault in vaults:
                vault_dir = vault_root / vault['path']
                hcl_path = vault_dir / "vault.hcl"
                log_file = open(vault_dir / "vault.log", "w")
                
                print(f"  -> Starting vault '{vault['alias']}' on port {vault['port']}...")
                proc = subprocess.Popen(
                    ["vault", "server", f"-config={hcl_path.resolve()}"],
                    cwd=str(vault_dir),
                    env=env,
                    stdout=log_file,
                    stderr=subprocess.STDOUT
                )
                self.processes.append((vault['alias'], proc, log_file))
            print("  -> Waiting 3s for vaults to bind to ports...")
            time.sleep(3)
        elif method == "stop":
            for alias, proc, log_file in self.processes:
                print(f"  -> Stopping '{alias}' (PID: {proc.pid})...")
                proc.terminate()
                log_file.close()
            self.processes.clear()
        elif method == "init":
            for vault in vaults:
                env = self._prepare_vault_env(vault)
                print(f"  -> Initializing '{vault['alias']}' at {env['VAULT_ADDR']}...")
                
                init_proc = subprocess.run(
                    ["vault", "operator", "init", "-format=json"],
                    env=env, capture_output=True, text=True
                )
                
                if init_proc.returncode == 0:
                    creds = json.loads(init_proc.stdout)
                    self.ram_credentials[vault['alias']] = creds
                    print(f"     [OK] Captured unseal keys and root token to RAM.")
                    print(f"     --- {vault['alias']} Credentials ---")
                    for i, key in enumerate(creds.get("unseal_keys_b64", [])):
                        print(f"     Unseal Key {i+1}: {key}")
                    print(f"     Initial Root Token: {creds.get('root_token')}")
                elif "Vault is already initialized" in init_proc.stderr:
                    print(f"     [Skip] Vault is already initialized.")
                else:
                    print(f"     [Error] Initialization failed: {init_proc.stderr.strip()}")
        elif method == "unseal":
            for vault in vaults:
                alias = vault['alias']
                if alias not in self.ram_credentials:
                    print(f"  -> [Skip] Cannot unseal '{alias}': no credentials in RAM.")
                    continue
                
                creds = self.ram_credentials[alias]
                keys = creds.get("unseal_keys_b64", [])
                if len(keys) < 3:
                    print(f"  -> [Error] Not enough unseal keys for '{alias}'.")
                    continue
                
                env = self._prepare_vault_env(vault)
                print(f"  -> Unsealing '{alias}' at {env['VAULT_ADDR']}...")
                
                for i in range(3):
                    res = subprocess.run(
                        ["vault", "operator", "unseal", keys[i]],
                        env=env, capture_output=True, text=True
                    )
                    if res.returncode != 0:
                        print(f"     [Error] Unseal failed on key {i+1}: {res.stderr.strip() or res.stdout.strip()}")
                        break
                else:
                    print(f"     [OK] Successfully unsealed '{alias}'.")
        elif method == "login":
            for vault in vaults:
                alias = vault['alias']
                if alias not in self.ram_credentials:
                    print(f"  -> [Skip] Cannot login to '{alias}': no credentials in RAM.")
                    continue
                
                root_token = self.ram_credentials[alias].get("root_token")
                if not root_token:
                    print(f"  -> [Error] No root token for '{alias}'.")
                    continue
                
                env = self._prepare_vault_env(vault)
                print(f"  -> Logging into '{alias}'...")
                
                res = subprocess.run(
                    ["vault", "login", root_token],
                    env=env, capture_output=True, text=True
                )
                if res.returncode == 0:
                    print(f"     [OK] Logged in successfully.")
                else:
                    print(f"     [Error] Login failed: {res.stderr.strip() or res.stdout.strip()}")
        elif method == "save_to_ram":
            print(f"  -> Confirmed {len(self.ram_credentials)} sets of credentials securely held in RAM.")
        elif method == "savecreds":
            mode = self.secure_storage_config.get('mode')
            payload = self.secure_storage_config.get('payload')
            if mode == 'vault' and payload:
                target_addr = payload
                print(f"  -> Transmitting {len(self.ram_credentials)} credentials to secure storage vault at '{target_addr}'...")
                
                target_token = os.environ.get("VAULT_TOKEN")
                if not target_token:
                    target_token = getpass.getpass(f"     Enter Vault token for {target_addr}: ")
                    
                # Strip invisible spaces/newlines that cause instant 403 Invalid Token errors
                target_token = target_token.strip()
                    
                target_env = os.environ.copy()
                target_env["VAULT_ADDR"] = target_addr
                target_env["VAULT_TOKEN"] = target_token
                # Force Vault CLI to ignore the ~/.vault-token file overwritten by the .login command
                target_env["VAULT_TOKEN_FILE"] = os.devnull
                
                for vault in vaults:
                    alias = vault['alias']
                    if alias in self.ram_credentials:
                        keys_data = self.ram_credentials[alias]
                        unseal_keys = keys_data.get("unseal_keys_b64", [])
                        if len(unseal_keys) >= 5:
                            out = {
                                "key1": unseal_keys[0],
                                "key2": unseal_keys[1],
                                "key3": unseal_keys[2],
                                "key4": unseal_keys[3],
                                "key5": unseal_keys[4],
                                "root": keys_data.get("root_token", "")
                            }
                            
                            # Wrap in "data" for KVv2 and use raw write to bypass preflight checks
                            payload = {"data": out}
                            res = subprocess.run(
                                ["vault", "write", f"kv/data/{alias}", "-"],
                                env=target_env, input=json.dumps(payload), text=True, capture_output=True
                            )
                            
                            if res.returncode == 0:
                                print(f"     [OK] Pushed '{alias}' credentials to KV store at kv/data/{alias}")
                            else:
                                print(f"     [Error] Failed to write to 'kv/data/{alias}': {res.stderr.strip() or res.stdout.strip()}")
                        else:
                            print(f"     [Error] Not enough keys for '{alias}' to save.")
            elif mode == 'file':
                vault_root = Path(self.globals.get("Single_vault_root", "./")).resolve()
                print(f"  -> Saving {len(self.ram_credentials)} credentials to plain text files (file mode)...")
                for vault in vaults:
                    alias = vault['alias']
                    if alias in self.ram_credentials:
                        keys_data = self.ram_credentials[alias]
                        unseal_keys = keys_data.get("unseal_keys_b64", [])
                        if len(unseal_keys) >= 5:
                            out = {
                                "key1": unseal_keys[0],
                                "key2": unseal_keys[1],
                                "key3": unseal_keys[2],
                                "key4": unseal_keys[3],
                                "key5": unseal_keys[4],
                                "root": keys_data.get("root_token", "")
                            }
                            vault_dir = vault_root / vault['path']
                            keys_file = vault_dir / "init_keys.json"
                            keys_file.write_text(json.dumps(out, indent=2))
                            keys_file.chmod(0o600)  # Secure the file to owner-only
                            print(f"     [OK] Wrote {keys_file}")
                        else:
                            print(f"     [Error] Not enough keys for '{alias}' to save.")
            else:
                print(f"  -> (Stub) Executing savecreds, but secure storage mode '{mode}' is not yet fully implemented.")
        elif method == "status":
            for vault in vaults:
                alias = vault['alias']
                env = self._prepare_vault_env(vault)
                print(f"  -> Checking status of '{alias}' at {env.get('VAULT_ADDR')}...")
                
                res = subprocess.run(
                    ["vault", "status", "-format=json"],
                    env=env, capture_output=True, text=True, timeout=5
                )
                
                if res.returncode != 0:
                    # Handle cases where the vault process isn't running at all
                    if "dial tcp" in res.stderr and "connection refused" in res.stderr:
                         print(f"     [FAIL] Connection refused. Vault process is likely not running.")
                    else:
                        print(f"     [FAIL] Command failed: {res.stderr.strip() or res.stdout.strip()}")
                    continue
                
                try:
                    status_data = json.loads(res.stdout)
                    sealed = status_data.get("sealed", False)
                    version = status_data.get("version", "N/A")
                    cluster_name = status_data.get("cluster_name", "N/A")
                    
                    if sealed:
                        print(f"     [SEALED] Version: {version}, Cluster: {cluster_name}")
                    else:
                        print(f"     [UNSEALED] Version: {version}, Cluster: {cluster_name}")
                except json.JSONDecodeError:
                    print(f"     [FAIL] Could not parse JSON from status output.")
        else:
            print(f"  -> Method '{method}' is not yet implemented.")

    def _get_vault_info(self, alias: str):
        """Helper to find vault configuration by alias name."""
        for coll in self.collections.values():
            for v in coll:
                if v['alias'] == alias:
                    return v
        return None

    def _prepare_vault_env(self, vault_info):
        """Builds an environment dictionary with the correct VAULT_ADDR and VAULT_CACERT based on vault state."""
        env = os.environ.copy()
        if vault_info.get("tls"):
            env["VAULT_ADDR"] = f"https://127.0.0.1:{vault_info['port']}"
            vault_root = Path(self.globals.get("Single_vault_root", "./")).resolve()
            ca_path = vault_root / "certstore" / vault_info["alias"] / "ca-chain.pem"
            if ca_path.exists():
                env["VAULT_CACERT"] = str(ca_path)
        else:
            env["VAULT_ADDR"] = f"http://127.0.0.1:{vault_info['port']}"
        return env

    def execute_targeted_op(self, action: str, role: str, target: str):
        vault = self._get_vault_info(target)
        if not vault:
            print(f"     [Error] Target vault '{target}' not found.")
            return

        if action == "add_role":
            if role == "unsealer":
                print(f"     -> Provisioning Transit Engine for '{target}'...")
                env = self._prepare_vault_env(vault)
                
                creds = self.ram_credentials.get(target)
                if creds and creds.get("root_token"):
                    env["VAULT_TOKEN"] = creds["root_token"]
                else:
                    print(f"     [Error] No root token in RAM for '{target}'. Cannot configure transit.")
                    return

                # 1. Enable transit secrets engine
                res_enable = subprocess.run(
                    ["vault", "secrets", "enable", "transit"],
                    env=env, capture_output=True, text=True
                )
                if res_enable.returncode == 0:
                    print("     [OK] Enabled 'transit' secrets engine.")
                elif "path is already in use at transit/" in res_enable.stderr:
                    print("     [Skip] 'transit' secrets engine already enabled.")
                else:
                    print(f"     [Error] Failed to enable transit: {res_enable.stderr.strip()}")

                # 2. Create the autounseal transit key
                res_key = subprocess.run(
                    ["vault", "write", "-f", "transit/keys/autounseal"],
                    env=env, capture_output=True, text=True
                )
                if res_key.returncode == 0:
                    print("     [OK] Created transit key 'autounseal'.")
                else:
                    print(f"     [Error] Failed to create transit key: {res_key.stderr.strip()}")
                    
            elif role == "unsealer_subscriber":
                print(f"     [Info] Role 'unsealer_subscriber' declared for '{target}'.")
            else:
                print(f"     [Stub] Role '{role}' is not fully implemented yet.")
        else:
            print(f"     [Error] Unknown targeted action '{action}'.")

    def execute_targeted_method(self, role: str, target: str, method: str, arg: str):
        if role == "unsealer_subscriber" and method == "subscribeTo":
            unsealer_vault = self._get_vault_info(arg)
            subscriber_vault = self._get_vault_info(target)
            
            if not unsealer_vault or not subscriber_vault:
                print(f"     [Error] Missing vault information for linking '{target}' to '{arg}'.")
                return
                
            print(f"     -> Linking '{target}' to transit unsealer '{arg}'...")
            
            # 1. Setup env to hit the Unsealer Vault
            env = self._prepare_vault_env(unsealer_vault)
            creds = self.ram_credentials.get(arg)
            if creds and creds.get("root_token"):
                env["VAULT_TOKEN"] = creds["root_token"]
            else:
                print(f"     [Error] No root token in RAM for unsealer '{arg}'. Cannot generate transit token.")
                return
                
            # 2. Write the policy on the unsealer
            policy_name = f"autounseal-{target}"
            policy_content = 'path "transit/encrypt/autounseal" { capabilities = [ "update" ] }\npath "transit/decrypt/autounseal" { capabilities = [ "update" ] }'
            
            vault_root = Path(self.globals.get("Single_vault_root", "./")).resolve()
            unsealer_dir = vault_root / unsealer_vault['path']
            policy_path = unsealer_dir / f"{policy_name}.hcl"
            policy_path.write_text(policy_content)
            
            subprocess.run(["vault", "policy", "write", policy_name, str(policy_path)], env=env, capture_output=True)
            
            # 3. Create a periodic orphan token for the subscriber
            res_tok = subprocess.run(
                ["vault", "token", "create", "-orphan", f"-policy={policy_name}", "-period=24h", "-format=json"],
                env=env, capture_output=True, text=True
            )
            if res_tok.returncode != 0:
                print(f"     [Error] Failed to create token: {res_tok.stderr.strip()}")
                return
                
            tok_data = json.loads(res_tok.stdout)
            client_token = tok_data["auth"]["client_token"]
            print(f"     [OK] Generated periodic transit token for '{target}'.")
            
            # 4. Append the seal block to the subscriber's HCL
            subscriber_dir = vault_root / subscriber_vault['path']
            hcl_path = subscriber_dir / "vault.hcl"
            seal_block = f'\nseal "transit" {{\n  address = "http://127.0.0.1:{unsealer_vault["port"]}"\n  disable_renewal = "false"\n  key_name = "autounseal"\n  mount_path = "transit/"\n  tls_skip_verify = "true"\n  token = "{client_token}"\n}}\n'
            
            with open(hcl_path, "a") as f:
                f.write(seal_block)
            print(f"     [OK] Appended transit seal block to {hcl_path}")
            
        elif role == "unsealer_subscriber" and method == "migrate":
            subscriber_vault = self._get_vault_info(target)
            if not subscriber_vault:
                print(f"     [Error] Target vault '{target}' not found.")
                return
                
            print(f"     -> Migrating '{target}' from shamir to transit seal...")
            env = self._prepare_vault_env(subscriber_vault)
            
            creds = self.ram_credentials.get(target)
            if not creds or "unseal_keys_b64" not in creds:
                print(f"     [Error] No unseal keys in RAM for '{target}'. Cannot migrate.")
                return
                
            keys = creds["unseal_keys_b64"]
            for i in range(3):
                res = subprocess.run(
                    ["vault", "operator", "unseal", "-migrate", keys[i]],
                    env=env, capture_output=True, text=True
                )
                if res.returncode != 0:
                    print(f"     [Error] Migration failed on key {i+1}: {res.stderr.strip() or res.stdout.strip()}")
                    break
            else:
                print(f"     [OK] Successfully migrated '{target}' to transit auto-unseal.")
        else:
            print(f"     [Error] Unknown method '{method}' for role '{role}'.")

    def execute_vault_command(self, command: str, target: str):
        vault_info = self._get_vault_info(target)
        if not vault_info:
            print(f"     [Error] Target vault '{target}' not found.")
            return

        if command == "start":
            vault_root = Path(self.globals.get("Single_vault_root", "./")).resolve()
            env = os.environ.copy()
            vault_dir = vault_root / vault_info['path']
            hcl_path = vault_dir / "vault.hcl"
            log_file = open(vault_dir / "vault.log", "a") # append so we don't wipe previous logs
            
            print(f"     -> Starting vault '{vault_info['alias']}' on port {vault_info['port']}...")
            proc = subprocess.Popen(
                ["vault", "server", f"-config={hcl_path.resolve()}"],
                cwd=str(vault_dir), env=env, stdout=log_file, stderr=subprocess.STDOUT
            )
            self.processes.append((vault_info['alias'], proc, log_file))
            time.sleep(1) # Brief wait for the single vault to bind
        elif command == "stop":
            found = False
            for proc_tuple in list(self.processes): # Iterate over a copy since we modify it
                alias, proc, log_file = proc_tuple
                if alias == target:
                    print(f"     -> Stopping '{alias}' (PID: {proc.pid})...")
                    proc.terminate()
                    log_file.close()
                    self.processes.remove(proc_tuple)
                    found = True
                    break
            if not found:
                print(f"     [Skip] Vault '{target}' is not currently running.")
        elif command == "tls_enable":
            print(f"     -> Enabling TLS for '{target}'...")
            vault_root = Path(self.globals.get("Single_vault_root", "./")).resolve()
            vault_dir = vault_root / vault_info['path']
            hcl_path = vault_dir / "vault.hcl"

            if not hcl_path.exists():
                print(f"     [Error] HCL file not found for '{target}' at {hcl_path}. Run deploy first.")
                return

            # Convention: certs are in 'certstore' under the root, named after the alias
            cert_dir = vault_root / "certstore" / target
            cert_file = cert_dir / "server-cert.pem"
            key_file = cert_dir / "server-key.pem"

            try:
                hcl_content = hcl_path.read_text()

                # Rebuild the listener block with TLS enabled
                new_listener_block = f"""listener "tcp" {{
  address     = "127.0.0.1:{vault_info['port']}"
  tls_disable = "false"
  tls_cert_file = "{cert_file.as_posix()}"
  tls_key_file = "{key_file.as_posix()}"
}}"""
                hcl_content = re.sub(r'listener "tcp" \{[^\}]*\}', new_listener_block, hcl_content, flags=re.DOTALL)

                # Update api_addr to use https
                hcl_content = re.sub(r'api_addr\s*=\s*"http://', 'api_addr = "https://', hcl_content)

                hcl_path.write_text(hcl_content)
                print(f"     [OK] Updated {hcl_path} with TLS configuration.")
            except Exception as e:
                print(f"     [Error] Failed to update HCL file for TLS: {e}")
        else:
            print(f"     [Error] Unknown vault command '{command}'.")

    def execute_transform(self, target: str, state: str):
        vault_info = self._get_vault_info(target)
        if not vault_info:
            print(f"  -> [Error] Transform failed: Target vault '{target}' not found.")
            return

        print(f"  -> [Action] Transforming '{target}' to state '{state}'...")
        if state == "tls_enabled":
            vault_info['tls'] = True
            print(f"     [OK] Vault '{target}' internal state updated to use HTTPS.")
        else:
            print(f"     [Error] Unknown transform state '{state}'.")

    def execute_pki_build(self, node: PKIBuildNode):
        print(f"  -> [Action] Building PKI with root '{node.root_alias}' and intermediate '{node.intermediate_alias}'...")

        cmd = ["python3", "vault_pki_doer.py", "rebuild-pki"]

        # Get all unique vaults from all collections
        all_vaults = []
        for coll in self.collections.values():
            all_vaults.extend(coll)
        
        seen_aliases = set()
        unique_vaults = []
        for v in all_vaults:
            if v['alias'] not in seen_aliases:
                unique_vaults.append(v)
                seen_aliases.add(v['alias'])

        # Build vault definitions for the doer script, assigning roles based on the pki_build arguments
        for vault in unique_vaults:
            alias = vault['alias']
            role = "leaf" # Default role
            if alias == node.root_alias:
                role = "root_ca"
            elif alias == node.intermediate_alias:
                role = "intermediate_ca"
            
            cmd.extend(["--vault-def", f"{alias}:127.0.0.1:{vault['port']}:{role}"])

        root_token = self.ram_credentials.get(node.root_alias, {}).get("root_token")
        if root_token:
            cmd.extend(["--root-ca-token", root_token])

        intermediate_token = self.ram_credentials.get(node.intermediate_alias, {}).get("root_token")
        if intermediate_token:
            cmd.extend(["--intermediate-ca-token", intermediate_token])

        cmd.extend(["--root-ca-alias", node.root_alias])
        cmd.extend(["--intermediate-ca-alias", node.intermediate_alias])
        
        vault_root = self.globals.get("Single_vault_root", "./")
        cmd.extend(["--vault-root", vault_root])

        print(f"     -> Executing: {' '.join(cmd)}")
        res = subprocess.run(cmd, shell=False, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"     [OK] PKI build command completed successfully.")
        else:
            print(f"     [Error] PKI build command failed with exit code {res.returncode}:\n{res.stderr.strip() or res.stdout.strip()}")
class CaedistInterpreter:
    def __init__(self, script_path: str):
        path = Path(script_path)
        if not path.exists():
            raise FileNotFoundError(f"Could not find DSL script: {script_path}")
            
        self.lexer = CaedistLexer(path.read_text())
        self.parser = CaedistParser(self.lexer.tokens)
        
        self.ast = None
    def debug_tokens(self):
        for token in self.lexer.tokens:
            print(token)

    def parse_and_print_ast(self):
        ast = self._get_ast()
        print("--- AST Output ---")
        print(json.dumps(ast.to_dict(), indent=2))

    def execute(self):
        evaluator = CaedistEvaluator(self._get_ast())
        evaluator.evaluate()

    def _get_ast(self):
        """Parse the token stream once and cache the result."""
        if self.ast is None:
            self.ast = self.parser.parse()
        return self.ast

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Execute a Caedist DSL file.")
    parser.add_argument("script", help="Path to the .caedist file to run")
    args = parser.parse_args()

    interpreter = CaedistInterpreter(args.script)
    print("--- Lexer Output ---")
    interpreter.debug_tokens()
    interpreter.parse_and_print_ast()
    interpreter.execute()