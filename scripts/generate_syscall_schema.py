#!/usr/bin/env python3

import argparse
import json
import re
from pathlib import Path


TYPE_QUALIFIERS = {"const", "volatile", "restrict", "__user"}

SCALAR_INT_TYPES = {
    "aio_context_t",
    "clockid_t",
    "gid_t",
    "int",
    "key_t",
    "mqd_t",
    "pid_t",
    "qid_t",
    "timer_t",
    "uid_t",
    "__s32",
}

SCALAR_UINT_TYPES = {
    "__u32",
    "__u64",
    "dev_t",
    "long",
    "size_t",
    "ssize_t",
    "u32",
    "u64",
    "unsigned",
    "unsigned char",
    "unsigned int",
    "unsigned long",
    "unsigned short",
}

MAX_ARGS = 6

SPECIAL_ARG_TYPES = {}


def load_json(path: Path) -> dict:
    with path.open() as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected top-level object")
    return data


def normalize_signature(sig: str) -> str:
    return " ".join(sig.strip().split())


def split_type_and_name(sig: str) -> tuple[str, str]:
    sig = normalize_signature(sig)
    if not sig:
        return "", ""

    parts = sig.split()
    if len(parts) == 1:
        return parts[0], ""

    return " ".join(parts[:-1]), parts[-1]


def normalize_type(typ: str, name: str) -> str:
    ptr_prefix = "*" * name.count("*")
    bare = name.lstrip("*")
    if bare.endswith("[]"):
        ptr_prefix += "*"

    tokens = [tok for tok in typ.split() if tok not in TYPE_QUALIFIERS]
    if ptr_prefix:
        if tokens:
            tokens[-1] = tokens[-1] + ptr_prefix
        else:
            tokens.append(ptr_prefix)

    normalized = " ".join(tokens)
    normalized = normalized.replace(" *", "*").replace("* ", "*")
    if normalized in {"char*", "const char*"}:
        return normalized.replace("*", " *")
    if normalized in {"char*const*", "const char*const*"}:
        return normalized.replace("const*", "const *").replace("char*", "char *")
    return normalized


def bare_name(name: str) -> str:
    return name.lstrip("*").removesuffix("[]")


def classify_argument(syscall_name: str, arg_index: int, sig: str) -> str:
    special = SPECIAL_ARG_TYPES.get((syscall_name, arg_index))
    if special is not None:
        return special

    typ, name = split_type_and_name(sig)
    normalized_type = normalize_type(typ, name)
    arg_name = bare_name(name)

    if syscall_name in {"read", "write"} and arg_index == 1 and normalized_type in {
        "char *",
        "const char *",
    }:
        return "VAR_ARG_BYTES"

    if normalized_type in {"char *", "const char *"}:
        return "VAR_ARG_STRING"
    if normalized_type in {"char *const *", "const char *const *"}:
        return "VAR_ARG_ARGV"

    if syscall_name in {"open", "openat"} and arg_name == "flags":
        return "ARG_FLAGS"

    if "fd" in arg_name or arg_name == "fildes":
        return "ARG_FD"
    if arg_name == "whence":
        return "ARG_INT"
    if arg_name in {"mask", "mode"}:
        return "ARG_MODE"

    if re.search(r"\b(?:umode_t|mode_t)\b", normalized_type):
        return "ARG_MODE"
    if re.search(r"\b(?:off_t|loff_t)\b", normalized_type):
        return "ARG_OFF"

    if "*" in normalized_type:
        return "ARG_PTR"

    if normalized_type in SCALAR_INT_TYPES:
        return "ARG_INT"
    if normalized_type in SCALAR_UINT_TYPES:
        return "ARG_UINT"
    if normalized_type.startswith("unsigned "):
        return "ARG_UINT"

    return "ARG_RAW"


def load_syscalls(path: Path) -> list[dict]:
    data = load_json(path)
    syscalls = data.get("syscalls")
    if not isinstance(syscalls, list):
        raise ValueError(f'{path}: expected "syscalls" to be a list')

    items = []
    for entry in syscalls:
        if not isinstance(entry, dict):
            continue

        name = entry.get("name")
        number = entry.get("number")
        signature = entry.get("signature")
        if not isinstance(name, str) or not isinstance(number, int) or not isinstance(signature, list):
            continue

        clean_sig = [arg for arg in signature if isinstance(arg, str)]
        arg_types = [
            classify_argument(name, idx, arg)
            for idx, arg in enumerate(clean_sig[:MAX_ARGS])
        ]
        items.append(
            {
                "name": name,
                "number": number,
                "signature": clean_sig,
                "arg_types": arg_types,
            }
        )

    items.sort(key=lambda item: item["number"])
    return items


def load_kernel_version(path: Path) -> str:
    data = load_json(path)
    kernel = data.get("kernel")
    if not isinstance(kernel, dict):
        return "unknown"
    version = kernel.get("version")
    if not isinstance(version, str) or not version:
        return "unknown"
    return version


def load_architecture_summary(path: Path) -> str:
    data = load_json(path)
    kernel = data.get("kernel")
    if not isinstance(kernel, dict):
        return "unknown"

    arch = kernel.get("architecture")
    abi = kernel.get("abi")

    arch_name = "unknown"
    arch_bits = None
    if isinstance(arch, dict):
        if isinstance(arch.get("name"), str) and arch["name"]:
            arch_name = arch["name"]
        if isinstance(arch.get("bits"), int):
            arch_bits = arch["bits"]

    abi_name = "unknown"
    abi_bits = None
    if isinstance(abi, dict):
        if isinstance(abi.get("name"), str) and abi["name"]:
            abi_name = abi["name"]
        if isinstance(abi.get("bits"), int):
            abi_bits = abi["bits"]

    arch_part = arch_name if arch_bits is None else f"{arch_name} ({arch_bits}-bit)"
    abi_part = abi_name if abi_bits is None else f"{abi_name} ({abi_bits}-bit ABI)"
    return f"{arch_part}, {abi_part}"


def render_nr_defines(syscalls: list[dict]) -> str:
    lines = []
    for item in syscalls:
        lines.append(f"#define __NR_{item['name']} {item['number']}")
    return "\n".join(lines)


def render_schema_entry(item: dict) -> str:
    arg_types = item["arg_types"] + ["ARG_NONE"] * (MAX_ARGS - len(item["arg_types"]))
    return "\n".join(
        [
            "\t{",
            f"\t .syscall_id = __NR_{item['name']},",
            f"\t .arg_count = {min(len(item['signature']), MAX_ARGS)},",
            f"\t .arg_types = {{{', '.join(arg_types[:MAX_ARGS])}}},",
            "\t },",
        ]
    )


def render_header(syscalls: list[dict], kernel_version: str, architecture: str) -> str:
    define_block = render_nr_defines(syscalls)
    schema_block = "\n".join(render_schema_entry(item) for item in syscalls)
    return "\n".join(
        [
            "/*",
            f" * Autogenerated from table.json from https://syscalls.mebeim.net/.",
            f" * Kernel version: {kernel_version}.",
            f" * Architecture: {architecture}.",
            " */",
            "#ifndef LITRACE_SYSCALL_SCHEMA_H",
            "#define LITRACE_SYSCALL_SCHEMA_H",
            "",
            define_block,
            "",
            "static const struct syscall_arg_schema syscall_schemas[] = {",
            schema_block,
            "};",
            "",
            "#endif",
            "",
        ]
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--table", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    syscalls = load_syscalls(args.table)
    kernel_version = load_kernel_version(args.table)
    architecture = load_architecture_summary(args.table)
    args.output.write_text(render_header(syscalls, kernel_version, architecture))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
