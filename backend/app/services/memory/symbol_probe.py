from __future__ import annotations

import argparse
import json
import sys


MARKER = "KAIRON_SYMBOL_REQUIREMENT="


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--symbols", required=True)
    args = parser.parse_args()

    from volatility3.cli import CommandLine
    from volatility3.framework.symbols.windows import pdbutil

    captured: list[dict[str, object]] = []

    def capture(cls, context, guid, age, pdb_name, symbol_table_class, config_path="pdbutility", progress_callback=None):
        architectures = {str(getattr(layer, "metadata", {}).get("architecture", "")).lower() for layer in context.layers.values()}
        architecture = "x64" if architectures & {"intel64", "x64", "amd64"} else "x86" if architectures & {"intel32", "x86"} else "arm64" if "arm64" in architectures else "x64"
        identity = {"pdb_name": str(pdb_name).strip("\x00"), "pdb_guid": str(guid).upper(), "pdb_age": int(age), "architecture": architecture}
        if identity not in captured:
            captured.append(identity)
        return None

    pdbutil.PDBUtility.load_windows_symbol_table = classmethod(capture)
    sys.argv = [
        "vol",
        "--offline",
        "--cache-path",
        args.cache,
        "--symbol-dirs",
        args.symbols,
        "-q",
        "-f",
        args.evidence,
        "-r",
        "json",
        "windows.info",
    ]
    try:
        CommandLine().run()
    except SystemExit:
        pass
    if len(captured) != 1:
        return 2
    sys.stdout.write(MARKER + json.dumps(captured[0], separators=(",", ":"), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
