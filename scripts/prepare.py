#!/usr/bin/env python3

import shutil
from pathlib import Path
import json


def main():
    src_directory = Path("src")
    bearssl_directory = src_directory / "bearssl"
    bearssl_source_directory = bearssl_directory / "src"
    bearssl_include_directory = bearssl_directory / "inc"
    native_stub = []
    ignored = []
    for source in bearssl_source_directory.rglob("*.c"):
        shutil.copyfile(source, src_directory / source.name)
        native_stub.append(source.name)
        ignored.append(source.name)
    for header in bearssl_source_directory.rglob("*.h"):
        shutil.copyfile(header, src_directory / header.name)
        ignored.append(header.name)
    for header in bearssl_include_directory.rglob("*.h"):
        shutil.copyfile(header, src_directory / header.name)
        ignored.append(header.name)
    native_stub.append("bearssl.c")
    native_stub.sort()
    ignored.sort()

    moon_pkg_path = src_directory / "moon.pkg.json"
    moon_pkg_json = json.loads(moon_pkg_path.read_text(encoding="utf-8"))
    moon_pkg_json["native-stub"] = native_stub
    moon_pkg_path.write_text(json.dumps(moon_pkg_json, indent=2) + "\n", encoding="utf-8")

    gitignore_path = src_directory / ".gitignore"
    gitignore_path.write_text("\n".join(ignored) + "\n")


if __name__ == "__main__":
    main()
