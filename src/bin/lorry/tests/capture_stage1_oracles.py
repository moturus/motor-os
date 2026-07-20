#!/usr/bin/env python3
"""Capture normalized Cargo 1.97/1.98 Stage-1 rustc oracle invocations."""

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path


MOTOR_TARGET = "x86_64-unknown-motor"


def command_output(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def normalize(value: str, replacements: list[tuple[str, str]]) -> str:
    for actual, replacement in replacements:
        value = value.replace(actual, replacement)
    return value


def parse_running_commands(
    stderr: str, replacements: list[tuple[str, str]], rustc: Path
) -> list[dict[str, object]]:
    invocations = []
    rustc_text = str(rustc)
    for line in stderr.splitlines():
        marker = "Running `"
        if marker not in line or not line.endswith("`"):
            continue
        rendered = line.split(marker, 1)[1][:-1]
        tokens = shlex.split(rendered)
        try:
            program_index = tokens.index(rustc_text)
        except ValueError:
            continue

        environment = []
        for token in tokens[:program_index]:
            if "=" not in token:
                raise ValueError(f"unexpected rustc environment token: {token!r}")
            key, value = token.split("=", 1)
            environment.append([key, normalize(value, replacements)])

        arguments = [normalize(token, replacements) for token in tokens[program_index + 1 :]]
        metadata = None
        extra_filename = None
        for index, argument in enumerate(arguments):
            if argument == "-C" and index + 1 < len(arguments):
                option = arguments[index + 1]
                if option.startswith("metadata="):
                    metadata = option.split("=", 1)[1]
                elif option.startswith("extra-filename="):
                    extra_filename = option.split("=", 1)[1]

        if metadata is None or extra_filename is None:
            raise ValueError("rustc oracle command omitted Cargo identity arguments")

        invocations.append(
            {
                "environment": environment,
                "program": normalize(rustc_text, replacements),
                "arguments": arguments,
                "metadata": metadata,
                "extra_filename": extra_filename,
            }
        )
    return invocations


def artifact_records(
    stdout: str, replacements: list[tuple[str, str]]
) -> list[dict[str, object]]:
    artifacts = []
    for line in stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        executable = message.get("executable")
        if executable is None:
            continue
        path = Path(executable)
        digest = hashlib.sha256()
        with path.open("rb") as artifact:
            while block := artifact.read(1024 * 1024):
                digest.update(block)
        artifacts.append(
            {
                "path": normalize(str(path), replacements),
                "bytes": path.stat().st_size,
                "sha256": digest.hexdigest(),
            }
        )
    if not artifacts:
        raise ValueError("Cargo oracle produced no executable artifact")
    return artifacts


def capture_case(
    cargo: Path,
    rustc: Path,
    package: Path,
    root: Path,
    case_name: str,
    release: bool,
    test: bool,
    target: str | None,
) -> dict[str, object]:
    target_dir = root / case_name / "target"
    home = root / case_name / "home"
    cargo_home = root / case_name / "cargo-home"
    target_dir.mkdir(parents=True)
    home.mkdir()
    cargo_home.mkdir()

    command = [str(cargo)]
    command.append("test" if test else "build")
    command.extend(
        [
            "--locked",
            "-vv",
            "--message-format=json",
            "--target-dir",
            str(target_dir),
        ]
    )
    if test:
        command.append("--no-run")
    if release:
        command.append("--release")
    if target is not None:
        command.extend(["--target", target])

    environment = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_TERM_COLOR": "never",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ["PATH"],
        "RUSTC": str(rustc),
        "TERM": "dumb",
    }
    result = subprocess.run(
        command,
        cwd=package,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{case_name} failed with status {result.returncode}\n{result.stderr}"
        )

    replacements = sorted(
        [
            (str(target_dir), "{TARGET_DIR}"),
            (str(package), "{PACKAGE}"),
            (str(cargo), "{CARGO}"),
            (str(rustc), "{RUSTC}"),
            (str(home), "{HOME}"),
            (str(cargo_home), "{CARGO_HOME}"),
        ],
        key=lambda item: len(item[0]),
        reverse=True,
    )
    invocations = parse_running_commands(result.stderr, replacements, rustc)
    if len(invocations) != 1:
        raise ValueError(
            f"{case_name} expected one rustc unit, captured {len(invocations)}"
        )

    return {
        "name": case_name,
        "command": "test" if test else "build",
        "profile": "release" if release else "dev",
        "target": target,
        "rustc": invocations[0],
        "artifacts": artifact_records(result.stdout, replacements),
    }


def capture_family(
    label: str,
    cargo: Path,
    native_rustc: Path,
    motor_rustc: Path,
    package: Path,
    root: Path,
) -> dict[str, object]:
    cases = []
    for target_name, rustc, target in (
        ("native", native_rustc, None),
        ("motor", motor_rustc, MOTOR_TARGET),
    ):
        for profile_name, release in (("dev", False), ("release", True)):
            for command_name, test in (("build", False), ("test", True)):
                cases.append(
                    capture_case(
                        cargo,
                        rustc,
                        package,
                        root / label,
                        f"{target_name}-{profile_name}-{command_name}",
                        release,
                        test,
                        target,
                    )
                )

    return {
        "schema-version": 1,
        "family": label,
        "cargo-version": command_output([str(cargo), "--version", "--verbose"]),
        "native-rustc-version": command_output(
            [str(native_rustc), "--version", "--verbose"]
        ),
        "motor-rustc-version": command_output(
            [str(motor_rustc), "--version", "--verbose"]
        ),
        "package": "src/bin/red",
        "cases": cases,
    }


def verify_families(first: dict[str, object], second: dict[str, object]) -> None:
    first_cases = {case["name"]: case for case in first["cases"]}
    second_cases = {case["name"]: case for case in second["cases"]}
    if first_cases.keys() != second_cases.keys():
        raise ValueError("Cargo family fixtures contain different cases")
    for name in first_cases:
        first_rustc = first_cases[name]["rustc"]
        second_rustc = second_cases[name]["rustc"]
        if (
            first_rustc["metadata"],
            first_rustc["extra_filename"],
        ) != (
            second_rustc["metadata"],
            second_rustc["extra_filename"],
        ):
            raise ValueError(f"Cargo identity families differ for {name}")
        if first_cases[name]["artifacts"] != second_cases[name]["artifacts"]:
            raise ValueError(f"Cargo artifacts differ for {name}")


def path_argument(value: str) -> Path:
    path = Path(value).resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"not a file: {value}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-1.97", required=True, type=path_argument)
    parser.add_argument("--cargo-1.98", required=True, type=path_argument)
    parser.add_argument("--native-rustc", required=True, type=path_argument)
    parser.add_argument("--motor-rustc", required=True, type=path_argument)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()

    package = arguments.package.resolve()
    if not (package / "Cargo.toml").is_file():
        parser.error(f"package has no Cargo.toml: {package}")
    arguments.output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="lorry-stage1-oracles-") as temporary:
        root = Path(temporary)
        cargo_197 = capture_family(
            "1.97",
            getattr(arguments, "cargo_1.97"),
            arguments.native_rustc,
            arguments.motor_rustc,
            package,
            root,
        )
        cargo_198 = capture_family(
            "1.98",
            getattr(arguments, "cargo_1.98"),
            arguments.native_rustc,
            arguments.motor_rustc,
            package,
            root,
        )
        verify_families(cargo_197, cargo_198)

    for name, fixture in (("cargo-1.97.json", cargo_197), ("cargo-1.98.json", cargo_198)):
        destination = arguments.output_dir / name
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n")
        temporary.replace(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
