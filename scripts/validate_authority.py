"""Fail-closed validation for the bounded synthetic Authority catalog."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

AUTHORITY_ID = "github:rcoccia/control-tower-authority"
EXPECTED_POLICY_IDS = {"CCA-001", "SEC-014", "DR-009", "FIN-006"}
RELAYEU_FACTS = {
    "platform",
    "environment",
    "data_classification",
    "jurisdiction",
    "internet_ingress",
}
REQUIRED_HEADINGS = (
    "Intent",
    "Applicability",
    "Required properties",
    "Expected evidence",
    "Exceptions and waivers",
    "Progressive disclosure",
)
REQUIRED_SKILLS = {
    "classify-data",
    "assess-cloud-workload",
    "assess-security-boundary",
    "request-policy-waiver",
}
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def is_literal(value: Any) -> bool:
    return isinstance(value, (str, bool))


def tracked(root: Path, relative_path: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", relative_path],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def policy_path(root: Path, value: Any, errors: list[str], policy_id: str) -> Path | None:
    if not isinstance(value, str):
        errors.append(f"{policy_id}: path must be a string")
        return None
    if "\\" in value:
        errors.append(f"{policy_id}: policy path must not contain backslashes")
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or value != pure.as_posix():
        errors.append(f"{policy_id}: unsafe policy path {value!r}")
        return None
    if not value.startswith("policies/") or not value.endswith(".md"):
        errors.append(f"{policy_id}: policy path must be a Markdown file under policies/")
        return None

    candidate = root.joinpath(*pure.parts)
    try:
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_root)
    except (FileNotFoundError, ValueError):
        errors.append(f"{policy_id}: policy path does not resolve inside the repository")
        return None
    if candidate.is_symlink():
        errors.append(f"{policy_id}: policy path must not be a symlink")
        return None
    if not candidate.is_file():
        errors.append(f"{policy_id}: policy file does not exist")
        return None
    if not tracked(root, value):
        errors.append(f"{policy_id}: policy file is not git-tracked")
        return None
    return candidate


def facts_in_rule(rule: Any, errors: list[str], location: str) -> set[str]:
    if not isinstance(rule, dict) or len(rule) != 1:
        errors.append(f"{location}: rule must contain exactly one operator")
        return set()
    operator, operands = next(iter(rule.items()))
    if operator == "all":
        if not isinstance(operands, list) or not operands:
            errors.append(f"{location}: all requires a non-empty rule list")
            return set()
        facts: set[str] = set()
        for index, nested_rule in enumerate(operands):
            facts.update(facts_in_rule(nested_rule, errors, f"{location}.all[{index}]"))
        return facts
    if operator not in {"equals", "in"}:
        errors.append(f"{location}: unsupported operator {operator!r}")
        return set()
    if not isinstance(operands, list) or len(operands) != 2 or not isinstance(operands[0], str):
        errors.append(f"{location}: {operator} requires a fact name and value")
        return set()
    fact, value = operands
    if fact not in RELAYEU_FACTS:
        errors.append(f"{location}: unsupported fact dependency {fact!r}")
    if operator == "equals":
        if not is_literal(value):
            errors.append(f"{location}: equals value must be a string or boolean")
    elif not isinstance(value, list) or not value or not all(is_literal(item) for item in value):
        errors.append(f"{location}: in requires a non-empty list of string or boolean literals")
    return {fact}


def validate_markdown(path: Path, policy_id: str, properties: list[Any], errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if "# " not in text or "SYNTHETIC DEMO POLICY" not in text:
        errors.append(f"{policy_id}: missing policy title or synthetic demo label")
    for heading in REQUIRED_HEADINGS:
        if f"## {heading}" not in text:
            errors.append(f"{policy_id}: missing required heading {heading!r}")
    for property_id in properties:
        if not isinstance(property_id, str):
            continue
        if f'<a id="{property_id}"></a>' not in text:
            errors.append(f"{policy_id}: missing stable property anchor {property_id!r}")


def parse_frontmatter(path: Path, errors: list[str]) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        errors.append(f"{path}: missing frontmatter opening delimiter")
        return {}
    end = text.find("\n---\n", 4)
    if end < 0:
        errors.append(f"{path}: missing frontmatter closing delimiter")
        return {}
    fields: dict[str, str] = {}
    for line in text[4:end].splitlines():
        key, separator, value = line.partition(":")
        if not separator or not key or not value.strip() or key in fields:
            errors.append(f"{path}: invalid frontmatter field")
            return {}
        fields[key] = value.strip()
    if set(fields) != {"name", "description"}:
        errors.append(f"{path}: frontmatter must contain only name and description")
    return fields


def validate_skills(root: Path, errors: list[str]) -> None:
    skills_root = root / ".github" / "skills"
    for name in REQUIRED_SKILLS:
        skill_path = skills_root / name / "SKILL.md"
        if not skill_path.is_file():
            errors.append(f"missing required skill {name}")
            continue
        fields = parse_frontmatter(skill_path, errors)
        if fields.get("name") != name:
            errors.append(f"{skill_path}: frontmatter name must be {name!r}")
        content = skill_path.read_text(encoding="utf-8")
        required_statement = (
            "does **not** select mandatory policy, grant a waiver, or author normative policy."
        )
        if required_statement not in " ".join(content.split()):
            errors.append(f"{skill_path}: missing advisory-only boundary statement")


def validate_repository(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    if not (root / ".github" / "CODEOWNERS").is_file():
        errors.append("missing .github/CODEOWNERS")
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return [f"cannot read manifest.json: {exc}"]
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "authority_id",
        "policies",
    }:
        return ["manifest.json must contain exactly schema_version, authority_id, and policies"]
    if manifest["schema_version"] != "0.1.0":
        errors.append("manifest schema_version must be '0.1.0'")
    if manifest["authority_id"] != AUTHORITY_ID:
        errors.append(f"manifest authority_id must be {AUTHORITY_ID!r}")
    policies = manifest["policies"]
    if not isinstance(policies, list):
        return errors + ["manifest policies must be a list"]

    policy_ids: set[str] = set()
    property_ids: set[str] = set()
    for index, policy in enumerate(policies):
        location = f"policies[{index}]"
        required_fields = {
            "id",
            "version",
            "effect",
            "path",
            "sha256",
            "properties",
            "applicability",
        }
        if not isinstance(policy, dict) or set(policy) != required_fields:
            errors.append(f"{location}: policy must contain exactly the required fields")
            continue
        policy_id = policy["id"]
        if not isinstance(policy_id, str) or not policy_id:
            errors.append(f"{location}: id must be a non-empty string")
            policy_id = location
        elif policy_id in policy_ids:
            errors.append(f"duplicate policy id {policy_id!r}")
        policy_ids.add(policy_id)
        if not isinstance(policy["version"], str) or not SEMVER.fullmatch(policy["version"]):
            errors.append(f"{policy_id}: version must be immutable semantic version text")
        if policy["effect"] != "mandatory":
            errors.append(f"{policy_id}: effect must be 'mandatory'")
        if not isinstance(policy["sha256"], str) or not SHA256.fullmatch(policy["sha256"]):
            errors.append(f"{policy_id}: sha256 must be a lowercase SHA-256 digest")
        properties = policy["properties"]
        if not isinstance(properties, list) or not properties or not all(
            isinstance(item, str) and item for item in properties
        ):
            errors.append(f"{policy_id}: properties must be a non-empty list of IDs")
            properties = []
        for property_id in properties:
            if property_id in property_ids:
                errors.append(f"duplicate property id {property_id!r}")
            property_ids.add(property_id)
        path = policy_path(root, policy["path"], errors, policy_id)
        if path is not None:
            actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_digest != policy["sha256"]:
                errors.append(f"{policy_id}: SHA-256 does not match policy bytes")
            validate_markdown(path, policy_id, properties, errors)

        applicability = policy["applicability"]
        if not isinstance(applicability, dict) or set(applicability) != {
            "fact_dependencies",
            "rule",
        }:
            errors.append(f"{policy_id}: applicability must contain fact_dependencies and rule")
            continue
        dependencies = applicability["fact_dependencies"]
        if (
            not isinstance(dependencies, list)
            or not dependencies
            or not all(isinstance(item, str) and item in RELAYEU_FACTS for item in dependencies)
            or len(set(dependencies)) != len(dependencies)
        ):
            errors.append(f"{policy_id}: fact_dependencies must be unique RelayEU facts")
            dependencies = []
        referenced = facts_in_rule(applicability["rule"], errors, f"{policy_id}.applicability")
        if set(dependencies) != referenced:
            errors.append(f"{policy_id}: fact_dependencies must exactly match rule facts")
    if policy_ids != EXPECTED_POLICY_IDS:
        errors.append("manifest must contain exactly CCA-001, SEC-014, DR-009, and FIN-006")
    validate_skills(root, errors)
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate_repository(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Authority validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
