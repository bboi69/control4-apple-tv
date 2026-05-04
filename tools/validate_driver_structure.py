#!/usr/bin/env python3
"""Validate the local Control4 driver package structure.

This is not a replacement for JumpStart or DriverPackager. It checks the
structure that JumpStart-generated SDK sample drivers use: a c4z project file
listing local driver assets, plus a parseable driver.xml with the expected root.
"""

from __future__ import annotations

import pathlib
import sys
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"validation failed: {message}")


def parse_xml(path: pathlib.Path) -> ET.Element:
    try:
        return ET.parse(path).getroot()
    except ET.ParseError as err:
        fail(f"{path.name} is not valid XML: {err}")


def main() -> None:
    driver_xml = ROOT / "driver.xml"
    driver_lua = ROOT / "driver.lua"
    project = ROOT / "driver.c4zproj"

    for path in [driver_xml, driver_lua, project]:
        if not path.exists():
            fail(f"missing {path.name}")

    driver_root = parse_xml(driver_xml)
    if driver_root.tag != "devicedata":
        fail("driver.xml root must be <devicedata>")

    project_root = parse_xml(project)
    if project_root.tag != "Driver":
        fail("driver.c4zproj root must be <Driver>")
    if project_root.attrib.get("type") != "c4z":
        fail('driver.c4zproj Driver type must be "c4z"')

    items = project_root.find("Items")
    if items is None:
        fail("driver.c4zproj must contain <Items>")

    included_files = set()
    for item in items.findall("Item"):
        if item.attrib.get("type") != "file":
            continue
        name = item.attrib.get("name")
        if not name:
            fail("file Item is missing name")
        included_files.add(name)
        if not (ROOT / name).exists():
            fail(f"project references missing file {name}")

    for required in ["driver.xml", "driver.lua"]:
        if required not in included_files:
            fail(f"driver.c4zproj must include {required}")

    proxies = driver_root.find("proxies")
    if proxies is None or not proxies.findall("proxy"):
        fail("driver.xml must define at least one proxy")

    connections = driver_root.find("connections")
    if connections is None:
        fail("driver.xml must contain <connections>")

    required_av_connections = {
        "2001": {"name": "AV Out", "type": "5", "class": "HDMI"},
        "4002": {"name": "AV Out", "type": "6", "class": "STEREO"},
        "1101": {"name": "Video In from App Switch", "type": "5", "class": "HDMI"},
        "2110": {"name": "App Switch Video Out", "type": "5", "class": "HDMI"},
        "4001": {"name": "Audio In from App Switch", "type": "6", "class": "STEREO"},
        "4110": {"name": "App Switch Audio Out", "type": "6", "class": "STEREO"},
    }
    by_id = {connection.findtext("id"): connection for connection in connections.findall("connection")}
    for binding_id, expected in required_av_connections.items():
        connection = by_id.get(binding_id)
        if connection is None:
            fail(f"driver.xml missing AV connection id {binding_id}")
        if connection.findtext("connectionname") != expected["name"]:
            fail(f"AV connection id {binding_id} must be named {expected['name']}")
        if connection.findtext("type") != expected["type"]:
            fail(f"AV connection id {binding_id} must have type {expected['type']}")
        if connection.findtext("facing") != "6":
            fail(f"AV connection id {binding_id} must define <facing>6</facing>")
        classes = {elem.findtext("classname") for elem in connection.findall("./classes/class")}
        if expected["class"] not in classes:
            fail(f"AV connection id {binding_id} must include class {expected['class']}")

    main_audio_classes = {
        elem.findtext("classname")
        for elem in by_id["4002"].findall("./classes/class")
    }
    for class_name in ["STEREO", "DIGITAL_COAX", "DIGITAL_OPTICAL"]:
        if class_name not in main_audio_classes:
            fail(f"main AV Out audio connection must include class {class_name}")

    config = driver_root.find("config")
    if config is None:
        fail("driver.xml must contain <config>")

    script = config.find("script")
    if script is None or script.attrib.get("file") != "driver.lua":
        fail('driver.xml config must reference <script file="driver.lua"/>')

    print("driver structure ok")


if __name__ == "__main__":
    main()
