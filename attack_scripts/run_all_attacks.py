from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER_NAME = Path(__file__).name


def attack_sort_key(path: Path) -> tuple[int, str]:
    match = re.search(r"attack_(\d+)_", path.stem)
    number = int(match.group(1)) if match else 9999
    return (number, path.name)


def discover_attack_scripts() -> list[Path]:
    scripts = [
        path
        for path in SCRIPT_DIR.glob("attack_*.py")
        if path.name != RUNNER_NAME
    ]
    return sorted(scripts, key=attack_sort_key)


def pretty_name(path: Path) -> str:
    return path.stem.replace("_", " ")


def run_script(path: Path) -> None:
    print(f"\n=== Running: {path.name} ===")
    try:
        result = subprocess.run([sys.executable, str(path)], check=False)
    except OSError as exc:
        print(f"[ERROR] Could not execute {path.name}: {exc}")
        return

    print(f"=== Finished: {path.name} (exit code {result.returncode}) ===")


def run_all(scripts: list[Path]) -> None:
    for script in scripts:
        run_script(script)


def show_menu(scripts: list[Path]) -> None:
    print("\nAvailable attacks:")
    for index, script in enumerate(scripts, start=1):
        print(f"{index}. {pretty_name(script)} ({script.name})")
    print("A. Run all attacks in sequence")
    print("Q. Quit")


def main() -> None:
    scripts = discover_attack_scripts()
    if not scripts:
        print("No attack scripts found.")
        return

    while True:
        show_menu(scripts)
        choice = input("\nPick an attack number (or A/Q): ").strip().lower()

        if choice == "q":
            print("Exiting.")
            return

        if choice == "a":
            run_all(scripts)
            continue

        if choice.isdigit():
            selected = int(choice)
            if 1 <= selected <= len(scripts):
                run_script(scripts[selected - 1])
                continue

        print("Invalid choice. Please enter a valid number, A, or Q.")


if __name__ == "__main__":
    main()
