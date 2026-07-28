#!/usr/bin/env python3
"""Validate the cross-client skbx agent plugin and marketplace catalogs."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "skbx"
CODEX_MANIFEST = PLUGIN / ".codex-plugin" / "plugin.json"
CLAUDE_MANIFEST = PLUGIN / ".claude-plugin" / "plugin.json"
CODEX_MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
CLAUDE_MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
SKILL = PLUGIN / "skills" / "use-skbx" / "SKILL.md"


def fail(message: str) -> None:
    raise ValueError(message)


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path.relative_to(ROOT)}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)}: root must be an object")
    return value


def require(value: object, message: str) -> None:
    if not value:
        fail(message)


def require_relative_file(raw_path: object, field: str) -> None:
    require(isinstance(raw_path, str), f"{field}: expected a string path")
    path = str(raw_path)
    require(path.startswith("./"), f"{field}: path must start with ./")
    resolved = (PLUGIN / path).resolve()
    require(PLUGIN.resolve() in resolved.parents, f"{field}: path escapes plugin root")
    require(resolved.is_file(), f"{field}: missing {path}")


def validate() -> None:
    codex = load_json(CODEX_MANIFEST)
    claude = load_json(CLAUDE_MANIFEST)
    codex_market = load_json(CODEX_MARKETPLACE)
    claude_market = load_json(CLAUDE_MARKETPLACE)

    require(codex.get("name") == "skbx", "Codex manifest name must be skbx")
    require(claude.get("name") == "skbx", "Claude manifest name must be skbx")
    require(
        codex.get("version") == claude.get("version"),
        "Codex and Claude plugin versions must match",
    )
    require(
        isinstance(codex.get("version"), str)
        and re.fullmatch(r"\d+\.\d+\.\d+", codex["version"]),
        "Plugin version must be strict semver",
    )
    require(codex.get("skills") == "./skills/", "Codex skills path must be ./skills/")

    interface = codex.get("interface")
    require(isinstance(interface, dict), "Codex manifest needs interface metadata")
    for field in (
        "displayName",
        "shortDescription",
        "longDescription",
        "developerName",
        "category",
        "defaultPrompt",
    ):
        require(interface.get(field), f"Codex interface.{field} is required")
    for field in ("composerIcon", "logo"):
        require_relative_file(interface.get(field), f"Codex interface.{field}")

    require(
        codex_market.get("name") == claude_market.get("name") == "skbx-tools",
        "Marketplace names must match skbx-tools",
    )
    for label, marketplace in (
        ("Codex", codex_market),
        ("Claude", claude_market),
    ):
        plugins = marketplace.get("plugins")
        require(
            isinstance(plugins, list) and len(plugins) == 1,
            f"{label} marketplace must expose exactly one plugin",
        )
        require(plugins[0].get("name") == "skbx", f"{label} entry name must be skbx")

    codex_entry = codex_market["plugins"][0]
    require(
        codex_entry.get("source")
        == {"source": "local", "path": "./plugins/skbx"},
        "Codex marketplace source must point to ./plugins/skbx",
    )
    require(
        codex_entry.get("policy")
        == {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
        "Codex marketplace policy changed unexpectedly",
    )
    require(codex_entry.get("category") == "Developer", "Codex category must be Developer")
    require(
        claude_market["plugins"][0].get("source") == "./plugins/skbx",
        "Claude marketplace source must point to ./plugins/skbx",
    )

    skill = SKILL.read_text(encoding="utf-8")
    require("[TODO:" not in skill, "Skill contains a TODO placeholder")
    frontmatter = re.match(r"\A---\n(.*?)\n---\n", skill, re.DOTALL)
    require(frontmatter, "Skill needs YAML frontmatter")
    require(
        re.search(r"^name:\s+use-skbx$", frontmatter.group(1), re.MULTILINE),
        "Skill frontmatter name must be use-skbx",
    )
    require(
        re.search(r"^description:\s+\S", frontmatter.group(1), re.MULTILINE),
        "Skill frontmatter needs a description",
    )


if __name__ == "__main__":
    try:
        validate()
    except (OSError, ValueError) as error:
        print(f"agent plugin validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("agent plugin validation passed")
