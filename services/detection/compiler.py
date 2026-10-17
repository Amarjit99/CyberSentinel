"""CyberSentinel AI — Sigma Rule Compiler & Safe AST Evaluator
Governing Decisions: ADR-0005, BASELINE_AND_NAMING.md
Traceability: CSAI-P3-DETECTION
"""

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from uuid import NAMESPACE_DNS, uuid5

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
    SigmaCondition,
)
from sigma.rule import SigmaRule

from schemas.enums import EventSeverityEnum

# Canonical field name mappings from standard Sigma conventions to CanonicalEvent
CANONICAL_FIELD_MAP: Dict[str, str] = {
    "image": "process_name",
    "processname": "process_name",
    "process_name": "process_name",
    "commandline": "command_line",
    "processcommandline": "command_line",
    "command_line": "command_line",
    "parentimage": "parent_process",
    "parent_process": "parent_process",
    "processid": "process_id",
    "process_id": "process_id",
    "user": "username",
    "username": "username",
    "targetusername": "username",
    "sourceip": "src_ip",
    "sourceaddress": "src_ip",
    "src_ip": "src_ip",
    "destinationip": "dst_ip",
    "destinationaddress": "dst_ip",
    "dst_ip": "dst_ip",
    "sourceport": "src_port",
    "src_port": "src_port",
    "destinationport": "dst_port",
    "dst_port": "dst_port",
    "queryname": "domain",
    "domain": "domain",
    "cs-uri-stem": "url",
    "c-uri": "url",
    "url": "url",
    "computername": "hostname",
    "hostname": "hostname",
    "host_id": "host_id",
    "user_id": "user_id",
    "hashes": "hash_sha256",
    "hash_sha256": "hash_sha256",
    "sha256": "hash_sha256",
    "event_type": "event_type",
    "source_type": "source_type",
    "source_name": "source_name",
}

# Maximum allowed size for a Sigma rule file (1 MB)
MAX_RULE_FILE_SIZE = 1_048_576


class SigmaCompilationError(Exception):
    """Raised when a Sigma rule fails validation or cannot be compiled safely."""

    pass


@dataclass
class CompiledSigmaRule:
    """Compiled representation of a Sigma detection rule with evaluated AST."""

    id: str
    title: str
    status: str
    severity: EventSeverityEnum
    description: str
    logsource: Dict[str, Any]
    tags: List[str]
    mitre_attack_ids: List[str]
    raw_yaml: str
    content_hash: str
    eval_func: Callable[[Dict[str, Any]], bool]
    version: str = "1.0.0"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def rule_id(self) -> str:
        """Alias for rule identifier."""
        return self.id

    def evaluate(self, event: Union[Dict[str, Any], Any]) -> bool:
        """Safely evaluate event or dict against this compiled rule."""
        try:
            if hasattr(event, "model_dump"):
                event_dict = event.model_dump(mode="json")
            elif isinstance(event, dict):
                event_dict = event
            else:
                return False
            return self.eval_func(event_dict)
        except Exception:
            return False


class SigmaCompiler:
    """Compiles SigmaHQ YAML rules into safe AST evaluators for CanonicalEvent streams."""

    def __init__(self) -> None:
        self._compiled_cache: Dict[str, CompiledSigmaRule] = {}

    def compile_from_yaml(self, yaml_content: str, source_path: Optional[str] = None) -> CompiledSigmaRule:
        """Parse and compile a raw YAML string into a CompiledSigmaRule."""
        if len(yaml_content.encode("utf-8")) > MAX_RULE_FILE_SIZE:
            raise SigmaCompilationError(
                f"Rule content exceeds maximum allowed size of {MAX_RULE_FILE_SIZE} bytes"
            )

        content_hash = hashlib.sha256(yaml_content.encode("utf-8")).hexdigest()
        if content_hash in self._compiled_cache:
            return self._compiled_cache[content_hash]

        try:
            collection = SigmaCollection.from_yaml(yaml_content)
        except Exception as ex:
            raise SigmaCompilationError(f"Malformed Sigma YAML syntax: {ex}") from ex

        if not collection.rules:
            raise SigmaCompilationError("No valid Sigma rules found in YAML document")

        rule_item = collection.rules[0]
        if not isinstance(rule_item, SigmaRule):
            raise SigmaCompilationError("Unsupported correlation rule type in Sigma detection pipeline")
        compiled = self._compile_sigma_rule(rule_item, raw_yaml=yaml_content, content_hash=content_hash)
        self._compiled_cache[content_hash] = compiled
        return compiled

    compile_rule_yaml = compile_from_yaml

    def compile_from_file(self, file_path: Union[str, Path]) -> CompiledSigmaRule:
        """Load and compile a Sigma rule from a filesystem path."""
        path = Path(file_path)
        if not path.is_file():
            raise SigmaCompilationError(f"Sigma rule file not found: {path}")

        file_size = path.stat().st_size
        if file_size > MAX_RULE_FILE_SIZE:
            raise SigmaCompilationError(
                f"Rule file {path.name} exceeds maximum allowed size of {MAX_RULE_FILE_SIZE} bytes"
            )

        content = path.read_text(encoding="utf-8")
        return self.compile_from_yaml(content, source_path=str(path))

    def _compile_sigma_rule(
        self, rule: SigmaRule, raw_yaml: str, content_hash: str
    ) -> CompiledSigmaRule:
        """Transform pySigma SigmaRule object into a CompiledSigmaRule."""
        # Rule Identifier
        if rule.id:
            rule_id = str(rule.id)
        else:
            # Deterministically derive UUIDv5 from rule content hash
            rule_id = str(uuid5(NAMESPACE_DNS, f"cybersentinel.rule.{content_hash}"))

        # Severity mapping
        raw_level = rule.level.name.lower() if rule.level else "informational"
        severity_map = {
            "critical": EventSeverityEnum.CRITICAL,
            "high": EventSeverityEnum.HIGH,
            "medium": EventSeverityEnum.MEDIUM,
            "low": EventSeverityEnum.LOW,
            "informational": EventSeverityEnum.INFORMATIONAL,
        }
        severity = severity_map.get(raw_level, EventSeverityEnum.INFORMATIONAL)

        # Tags and MITRE ATT&CK technique extraction
        raw_tags = [str(t) for t in (rule.tags or [])]
        mitre_ids = []
        for t in raw_tags:
            match = re.search(r"(?:attack\.)?(t\d{4}(?:\.\d{3})?)", t.lower())
            if match:
                mitre_ids.append(match.group(1).upper())

        # Compile detection condition AST
        if not rule.detection or not rule.detection.parsed_condition:
            raise SigmaCompilationError(f"Rule '{rule.title}' contains no valid detection conditions")

        root_condition: SigmaCondition = rule.detection.parsed_condition[0]
        if not root_condition.parsed:
            raise SigmaCompilationError(f"Rule '{rule.title}' condition failed to parse into AST")

        eval_func = self._compile_ast_node(root_condition.parsed)

        return CompiledSigmaRule(
            id=rule_id,
            title=rule.title or "Untitled Detection Rule",
            status=rule.status.name.lower() if rule.status else "test",
            severity=severity,
            description=rule.description or "",
            logsource=rule.logsource.to_dict() if hasattr(rule.logsource, "to_dict") else {},
            tags=raw_tags,
            mitre_attack_ids=sorted(list(set(mitre_ids))),
            raw_yaml=raw_yaml,
            content_hash=content_hash,
            eval_func=eval_func,
        )

    def _compile_ast_node(self, node: Any) -> Callable[[Dict[str, Any]], bool]:
        """Recursively compile a pySigma AST node into a deterministic callable."""
        if isinstance(node, ConditionAND):
            sub_evaluators = [self._compile_ast_node(arg) for arg in node.args]
            return lambda ev: all(f(ev) for f in sub_evaluators)

        elif isinstance(node, ConditionOR):
            sub_evaluators = [self._compile_ast_node(arg) for arg in node.args]
            return lambda ev: any(f(ev) for f in sub_evaluators)

        elif isinstance(node, ConditionNOT):
            if not node.args:
                return lambda ev: False
            sub_evaluator = self._compile_ast_node(node.args[0])
            return lambda ev: not sub_evaluator(ev)

        elif isinstance(node, ConditionFieldEqualsValueExpression):
            raw_field = str(node.field).lower()
            canonical_field = CANONICAL_FIELD_MAP.get(raw_field, raw_field)
            val = node.value
            pattern = val.to_plain() if hasattr(val, "to_plain") else str(val)
            return lambda ev: self._match_field_value(ev, canonical_field, pattern)

        elif isinstance(node, ConditionValueExpression):
            # Global keyword search across all event string fields
            val = node.value
            pattern = val.to_plain() if hasattr(val, "to_plain") else str(val)
            return lambda ev: self._match_keyword(ev, pattern)

        else:
            raise SigmaCompilationError(f"Unsupported AST node type: {type(node).__name__}")

    @staticmethod
    def _match_field_value(event: Dict[str, Any], field_name: str, pattern: str) -> bool:
        """Match event field against Sigma string pattern with wildcard/containment support."""
        # 1. Lookup field in canonical event or nested entities
        actual_val = event.get(field_name)
        if actual_val is None:
            # Check nested entities dict
            entities = event.get("entities")
            if isinstance(entities, dict):
                actual_val = entities.get(field_name)

        if actual_val is None:
            return False

        actual_str = str(actual_val).lower()
        pat_lower = str(pattern).lower()

        # Check wildcard patterns (*term*, *term, term*)
        if pat_lower.startswith("*") and pat_lower.endswith("*") and len(pat_lower) >= 2:
            return pat_lower[1:-1] in actual_str
        elif pat_lower.startswith("*"):
            return actual_str.endswith(pat_lower[1:])
        elif pat_lower.endswith("*"):
            return actual_str.startswith(pat_lower[:-1])

        # Standard fnmatch for internal wildcards (e.g. *powershell*download*)
        if "*" in pat_lower or "?" in pat_lower:
            return fnmatch.fnmatch(actual_str, pat_lower)

        # Exact case-insensitive match
        return actual_str == pat_lower

    @staticmethod
    def _match_keyword(event: Dict[str, Any], pattern: str) -> bool:
        """Global keyword containment search across all scalar fields."""
        pat_lower = str(pattern).lower().strip("*")
        for k, v in event.items():
            if isinstance(v, (str, int, float)) and pat_lower in str(v).lower():
                return True
        return False

    def clear_cache(self) -> None:
        """Invalidate compiled rule cache."""
        self._compiled_cache.clear()
