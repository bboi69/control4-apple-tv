#!/usr/bin/env python3
"""Create a simple c4z archive from driver.c4zproj.

This is intentionally small and conservative. It mirrors the project file's
file items into a zip-compatible .c4z so the artifact can be loaded for early
Composer testing when DriverPackager is not available locally.
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def archive_name(item_name: str, c4z_dir: str) -> str:
    name = Path(item_name).as_posix()
    if c4z_dir:
        name = Path(item_name).name
        return f"{c4z_dir.rstrip('/')}/{name}"
    return name


def package(project_path: Path, output_path: Path) -> None:
    project = ET.parse(project_path).getroot()
    if project.tag != "Driver" or project.attrib.get("type") != "c4z":
        raise SystemExit("driver.c4zproj must have <Driver type=\"c4z\"> as root")

    items = project.find("Items")
    if items is None:
        raise SystemExit("driver.c4zproj must contain <Items>")

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in items.findall("Item"):
            if item.attrib.get("type") != "file":
                raise SystemExit("package_driver.py currently supports file items only")

            source = (project_path.parent / item.attrib["name"]).resolve()
            if not source.exists():
                raise SystemExit(f"project item does not exist: {source}")

            zf.write(source, archive_name(item.attrib["name"], item.attrib.get("c4zDir", "")))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", default="driver.c4zproj")
    parser.add_argument("--output", default="control4_apple_tv.c4z")
    args = parser.parse_args()

    project_path = (ROOT / args.project).resolve()
    output_path = (ROOT / args.output).resolve()
    package(project_path, output_path)
    print(f"created {output_path}")


if __name__ == "__main__":
    main()
