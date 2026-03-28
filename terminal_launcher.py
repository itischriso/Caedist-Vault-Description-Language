import os
import platform
import shutil
import subprocess
from pathlib import Path

TERMINAL_HINTS = {
    "linux": (
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "xterm",
    ),
}

def quote_posix(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"

def spawn_terminal(alias: str, port: str, path: str, vault_root: Path):
    """Launches an OS-specific terminal initialized for a specific Vault."""
    vault_dir = (vault_root / path).resolve()
    addr = f"http://127.0.0.1:{port}"
    
    # Build the bash command to set up the environment and drop into a shell
    script = (
        f'export VAULT_ADDR={quote_posix(addr)}; '
        f'export VAULT_SKIP_VERIFY=true; '
        f'cd {quote_posix(str(vault_dir))}; '
        'echo "==========================================================="; '
        f'echo " Connected to: {alias} at {addr}"; '
        'echo " Use vault status or vault login to interact."; '
        'echo "==========================================================="; '
        'exec bash'
    )
    
    command = ["bash", "-lc", script]
    title = f"{alias} terminal"

    system = platform.system()
    if system == "Windows":
        _launch_windows(title, vault_dir, command)
    elif system == "Linux":
        _launch_linux(title, vault_dir, command)
    else:
        print(f"Unsupported platform for terminal launch: {system}")

def _launch_windows(title: str, cwd: Path, command: list[str]):
    wt = shutil.which("wt") or shutil.which("wt.exe")
    if not wt:
        print("Windows Terminal (wt) not found")
        return
    args = [wt, "new-tab", "-d", str(cwd), "--title", title]
    args.extend(command)
    subprocess.Popen(args, cwd=str(cwd))

def _launch_linux(title: str, cwd: Path, command: list[str]):
    for name in TERMINAL_HINTS["linux"]:
        exe = shutil.which(name)
        if not exe:
            continue
        
        if name == "gnome-terminal":
            subprocess.Popen([exe, "--title", title, "--", *command], cwd=str(cwd), env=os.environ.copy())
        elif name == "konsole":
            subprocess.Popen([exe, "--workdir", str(cwd), "-p", f"tabtitle={title}", "-e", *command], cwd=str(cwd), env=os.environ.copy())
        elif name == "xfce4-terminal":
            subprocess.Popen([exe, "--title", title, "--working-directory", str(cwd), "--command", " ".join(command)], cwd=str(cwd), env=os.environ.copy())
        elif name == "xterm":
            subprocess.Popen([exe, "-T", title, "-e", *command], cwd=str(cwd), env=os.environ.copy())
        return
    print("No supported Linux terminal emulator found.")