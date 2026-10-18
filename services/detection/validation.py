"""CyberSentinel AI — Sigma Rule Static Validation & Diagnostics (Sprint 19)
Governing Decisions: ADR-0004, ADR-0005, Phase 19 Specification
"""

import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Set

import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from attack.registry import AttackCatalog, attack_catalog
from schemas.canonical_event import CanonicalEvent
from services.detection.compiler import CANONICAL_FIELD_MAP, MAX_RULE_FILE_SIZE
from services.detection.models import (
    RuleValidationReport,
    ValidationDiagnostic,
    ValidationSeverityEnum,
    utc_now,
)

logger = logging.getLogger("cybersentinel.detection.validation")

# Supported and known logsource values for normalized telemetry
KNOWN_LOGSOURCE_CATEGORIES: Set[str] = {
    "process_creation",
    "network_connection",
    "dns_query",
    "authentication",
    "file_event",
    "web_access",
    "registry_event",
}

KNOWN_LOGSOURCE_PRODUCTS: Set[str] = {
    "windows",
    "linux",
    "network",
    "cloud",
    "macos",
}

VALID_STATUSES: Set[str] = {"experimental", "test", "stable", "deprecated"}
VALID_LEVELS: Set[str] = {"informational", "low", "medium", "high", "critical"}


class SigmaRuleValidator:
    """Multi-layer static validator enforcing syntax, schema, ATT&CK, and quality constraints."""

    def __init__(self, catalog: Optional[AttackCatalog] = None):
        self.catalog = catalog or attack_catalog
        self._canonical_fields: Set[str] = set(CanonicalEvent.model_fields.keys()) | set(CANONICAL_FIELD_MAP.keys())

    def validate_yaml(
        self,
        yaml_content: str,
        existing_active_rule_ids: Optional[Set[str]] = None,
    ) -> RuleValidationReport:
        """Execute exhaustive validation on raw Sigma YAML rule text."""
        diagnostics: List[ValidationDiagnostic] = []
        unsupported: List[str] = []
        parsed_logsource: Dict[str, Any] = {}
        detected_attack_ids: List[str] = []
        rule_id: Optional[str] = None
        rule_title: Optional[str] = None

        # 1. Size bounds check
        content_bytes = yaml_content.encode("utf-8")
        if len(content_bytes) > MAX_RULE_FILE_SIZE:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.ERROR,
                    code="RULE_OVERSIZED",
                    field="file_size",
                    message=f"Rule exceeds maximum allowed size of {MAX_RULE_FILE_SIZE} bytes.",
                    suggested_fix="Reduce rule size or split into multiple detection rules.",
                )
            )
            return self._build_report(False, rule_id, rule_title, diagnostics, parsed_logsource, detected_attack_ids, unsupported)

        # 2. YAML syntax parse
        try:
            raw_doc = yaml.safe_load(yaml_content)
        except Exception as ex:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.ERROR,
                    code="INVALID_YAML_SYNTAX",
                    field="document",
                    message=f"YAML parsing failed: {ex}",
                    suggested_fix="Verify YAML indentation, quoting, and list markers.",
                )
            )
            return self._build_report(False, rule_id, rule_title, diagnostics, parsed_logsource, detected_attack_ids, unsupported)

        if not isinstance(raw_doc, dict):
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.ERROR,
                    code="INVALID_DOCUMENT_STRUCTURE",
                    field="document",
                    message="Sigma document must be a YAML mapping (dictionary).",
                    suggested_fix="Ensure top-level YAML keys are key-value pairs.",
                )
            )
            return self._build_report(False, rule_id, rule_title, diagnostics, parsed_logsource, detected_attack_ids, unsupported)

        # 3. Document structure & required top-level fields
        rule_title = str(raw_doc.get("title") or "").strip()
        if not rule_title or len(rule_title) < 3:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.ERROR,
                    code="MISSING_TITLE",
                    field="title",
                    message="Rule 'title' is missing or shorter than 3 characters.",
                    suggested_fix="Add a concise, descriptive title (e.g., 'Suspicious Certutil Download').",
                )
            )

        raw_id = raw_doc.get("id")
        if not raw_id:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.WARNING,
                    code="MISSING_RULE_ID",
                    field="id",
                    message="Rule is missing a standard UUID 'id' field.",
                    suggested_fix="Generate and include a unique UUIDv4 identifier.",
                )
            )
        else:
            rule_id = str(raw_id).strip()
            try:
                uuid.UUID(rule_id)
            except ValueError:
                diagnostics.append(
                    ValidationDiagnostic(
                        severity=ValidationSeverityEnum.WARNING,
                        code="INVALID_UUID_FORMAT",
                        field="id",
                        message=f"Rule ID '{rule_id}' is not a valid UUID format.",
                        suggested_fix="Use a standard 36-character hyphenated UUID (UUIDv4).",
                    )
                )

        # Duplicate ID check against active production rules
        if rule_id and existing_active_rule_ids and rule_id in existing_active_rule_ids:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.WARNING,
                    code="DUPLICATE_RULE_ID",
                    field="id",
                    message=f"Rule ID '{rule_id}' matches an already active production rule. This candidate will update or overwrite the active rule.",
                    suggested_fix="Assign a new UUID if this is an independent detection rule, or bump the version.",
                )
            )

        status_val = str(raw_doc.get("status") or "").lower().strip()
        if not status_val or status_val not in VALID_STATUSES:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.INFO,
                    code="NON_STANDARD_STATUS",
                    field="status",
                    message=f"Status '{status_val}' is non-standard. Expected one of: {sorted(VALID_STATUSES)}.",
                    suggested_fix="Set status to 'experimental', 'test', or 'stable'.",
                )
            )

        level_val = str(raw_doc.get("level") or "").lower().strip()
        if not level_val or level_val not in VALID_LEVELS:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.ERROR,
                    code="INVALID_SEVERITY_LEVEL",
                    field="level",
                    message=f"Alert level '{level_val}' is invalid. Must be one of: {sorted(VALID_LEVELS)}.",
                    suggested_fix="Specify a valid severity: informational, low, medium, high, or critical.",
                )
            )

        false_positives = raw_doc.get("falsepositives")
        if not isinstance(false_positives, list) or not any(str(item).strip() for item in false_positives):
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.WARNING,
                    code="MISSING_FALSE_POSITIVE_METADATA",
                    field="falsepositives",
                    message="Rule should document known benign matches for analyst review.",
                    suggested_fix="Add one or more concrete false-positive scenarios.",
                )
            )
        data_sources = raw_doc.get("data_sources")
        if not isinstance(data_sources, list) or not any(str(item).strip() for item in data_sources):
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.WARNING,
                    code="MISSING_DATA_SOURCE_METADATA",
                    field="data_sources",
                    message="Rule should identify the telemetry source fields required for evaluation.",
                    suggested_fix="Add one or more data-source names such as process_creation or dns_query.",
                )
            )

        # 4. Logsource validation
        logsource = raw_doc.get("logsource")
        if not isinstance(logsource, dict) or not logsource:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.ERROR,
                    code="MISSING_LOGSOURCE",
                    field="logsource",
                    message="Rule is missing a valid 'logsource' mapping.",
                    suggested_fix="Specify logsource with 'category' (e.g. process_creation) and 'product' (e.g. windows).",
                )
            )
        else:
            parsed_logsource = logsource
            cat = str(logsource.get("category") or "").lower().strip()
            prod = str(logsource.get("product") or "").lower().strip()

            if cat and cat not in KNOWN_LOGSOURCE_CATEGORIES:
                diagnostics.append(
                    ValidationDiagnostic(
                        severity=ValidationSeverityEnum.WARNING,
                        code="UNKNOWN_LOGSOURCE_CATEGORY",
                        field="logsource.category",
                        message=f"Category '{cat}' is not in the canonical logsource taxonomy: {sorted(KNOWN_LOGSOURCE_CATEGORIES)}.",
                        suggested_fix="Ensure category aligns with available telemetry schemas (e.g., process_creation, network_connection).",
                    )
                )

            if prod and prod not in KNOWN_LOGSOURCE_PRODUCTS:
                diagnostics.append(
                    ValidationDiagnostic(
                        severity=ValidationSeverityEnum.INFO,
                        code="UNKNOWN_LOGSOURCE_PRODUCT",
                        field="logsource.product",
                        message=f"Product '{prod}' is non-standard for this platform. Common products: {sorted(KNOWN_LOGSOURCE_PRODUCTS)}.",
                        suggested_fix="Specify product as 'windows', 'linux', or 'network'.",
                    )
                )

        # 5. Detection block and conditions validation
        detection = raw_doc.get("detection")
        if not isinstance(detection, dict) or not detection:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.ERROR,
                    code="MISSING_DETECTION_BLOCK",
                    field="detection",
                    message="Rule is missing a 'detection' block with selection and condition criteria.",
                    suggested_fix="Define selections and a condition (e.g., condition: selection).",
                )
            )
        else:
            condition = detection.get("condition")
            if not condition or not isinstance(condition, str):
                diagnostics.append(
                    ValidationDiagnostic(
                        severity=ValidationSeverityEnum.ERROR,
                        code="MISSING_CONDITION",
                        field="detection.condition",
                        message="Detection block is missing a non-empty string 'condition'.",
                        suggested_fix="Add a condition statement (e.g., 'selection and not filter').",
                    )
                )
            else:
                # Unsupported operator check (aggregations, correlations)
                lower_cond = condition.lower()
                if any(k in lower_cond for k in ["count()", "count(", "avg(", "sum(", "min(", "max("]):
                    unsupported.append("aggregation_functions")
                    diagnostics.append(
                        ValidationDiagnostic(
                            severity=ValidationSeverityEnum.ERROR,
                            code="UNSUPPORTED_AGGREGATION",
                            field="detection.condition",
                            message="Aggregation functions ('count()', 'avg()') are not supported in standard single-event Sigma detection.",
                            suggested_fix="Convert aggregation logic into sliding-window correlation rules.",
                        )
                    )

                # Check condition selection references
                defined_selections = {k for k in detection.keys() if k != "condition"}
                # Tokenize condition identifiers
                cond_tokens = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_*]*\b", condition))
                reserved_words = {"and", "or", "not", "all", "of", "them", "1"}
                referenced_selections = {t for t in cond_tokens if t.lower() not in reserved_words}

                for ref in referenced_selections:
                    # Allow wildcard references like 'selection_*' or 'sel*'
                    if ref.endswith("*"):
                        prefix = ref[:-1]
                        if not any(k.startswith(prefix) for k in defined_selections):
                            diagnostics.append(
                                ValidationDiagnostic(
                                    severity=ValidationSeverityEnum.ERROR,
                                    code="UNDEFINED_WILDCARD_SELECTION",
                                    field="detection.condition",
                                    message=f"Condition references wildcard pattern '{ref}', but no matching selections were defined.",
                                    suggested_fix=f"Define selections starting with '{prefix}'.",
                                )
                            )
                    elif ref not in defined_selections:
                        diagnostics.append(
                            ValidationDiagnostic(
                                severity=ValidationSeverityEnum.ERROR,
                                code="UNDEFINED_SELECTION_REFERENCE",
                                field="detection.condition",
                                message=f"Condition references selection '{ref}' which is not defined in detection block.",
                                suggested_fix=f"Add definition for '{ref}:' in detection block or remove from condition.",
                            )
                        )

            # 6. Field names and values inspection in selections
            for sel_name, sel_content in detection.items():
                if sel_name == "condition":
                    continue

                if isinstance(sel_content, dict):
                    self._validate_selection_dict(sel_name, sel_content, diagnostics)
                elif isinstance(sel_content, list):
                    for idx, item in enumerate(sel_content):
                        if isinstance(item, dict):
                            self._validate_selection_dict(f"{sel_name}[{idx}]", item, diagnostics)

        # 7. MITRE ATT&CK tags validation
        tags = raw_doc.get("tags") or []
        if isinstance(tags, list):
            for t in tags:
                tag_str = str(t).strip()
                match = re.search(r"(?:attack\.)?(t\d{4}(?:\.\d{3})?)", tag_str.lower())
                if match:
                    tech_id = match.group(1).upper()
                    detected_attack_ids.append(tech_id)
                    tech = self.catalog.get_technique(tech_id)
                    if not tech:
                        diagnostics.append(
                            ValidationDiagnostic(
                                severity=ValidationSeverityEnum.WARNING,
                                code="ATTACK_TECHNIQUE_NOT_IN_CATALOG",
                                field="tags",
                                message=f"ATT&CK technique '{tech_id}' was not found in the local enterprise catalog.",
                                suggested_fix="Verify technique ID against MITRE ATT&CK enterprise catalog.",
                            )
                        )

        # 8. pySigma Parser AST Compilation Verification
        try:
            collection = SigmaCollection.from_yaml(yaml_content)
            if not collection.rules:
                diagnostics.append(
                    ValidationDiagnostic(
                        severity=ValidationSeverityEnum.ERROR,
                        code="EMPTY_SIGMA_RULESET",
                        field="detection",
                        message="pySigma parsed zero rules from document.",
                        suggested_fix="Ensure rule defines required title, logsource, and detection condition.",
                    )
                )
            else:
                rule_obj = collection.rules[0]
                if not isinstance(rule_obj, SigmaRule):
                    unsupported.append("non_standard_rule_class")
                    diagnostics.append(
                        ValidationDiagnostic(
                            severity=ValidationSeverityEnum.ERROR,
                            code="UNSUPPORTED_RULE_CLASS",
                            field="document",
                            message=f"Rule type '{type(rule_obj).__name__}' is not supported in streaming evaluation.",
                            suggested_fix="Use standard SigmaRule document structure.",
                        )
                    )
        except Exception as ex:
            diagnostics.append(
                ValidationDiagnostic(
                    severity=ValidationSeverityEnum.ERROR,
                    code="PYSIGMA_PARSE_ERROR",
                    field="detection",
                    message=f"pySigma compiler failed parsing rule: {ex}",
                    suggested_fix="Fix Sigma condition or modifier syntax to comply with pySigma specification.",
                )
            )

        # Deduplicate detected ATT&CK techniques
        detected_attack_ids = sorted(list(set(detected_attack_ids)))

        # Determine overall validity
        is_valid = not any(d.severity == ValidationSeverityEnum.ERROR for d in diagnostics)

        return self._build_report(
            is_valid=is_valid,
            rule_id=rule_id,
            rule_title=rule_title,
            diagnostics=diagnostics,
            parsed_logsource=parsed_logsource,
            detected_attack_ids=detected_attack_ids,
            unsupported=unsupported,
        )

    def _validate_selection_dict(
        self,
        sel_name: str,
        sel_dict: Dict[str, Any],
        diagnostics: List[ValidationDiagnostic],
    ) -> None:
        """Validate fields and values inside a selection block."""
        for raw_field_expr, val in sel_dict.items():
            # Field expression may have modifiers, e.g. 'command_line|contains'
            parts = str(raw_field_expr).split("|")
            field_name = parts[0].strip().lower()
            modifiers = [m.lower() for m in parts[1:]]

            # Modifier validation
            supported_mods = {"contains", "endswith", "startswith", "re", "all", "base64", "wide", "utf16le", "utf16be", "cased"}
            for mod in modifiers:
                if mod not in supported_mods:
                    diagnostics.append(
                        ValidationDiagnostic(
                            severity=ValidationSeverityEnum.WARNING,
                            code="UNSUPPORTED_MODIFIER",
                            field=f"detection.{sel_name}.{raw_field_expr}",
                            message=f"Modifier '|{mod}' is uncommon or unsupported by current engine.",
                            suggested_fix="Use supported modifiers: contains, startswith, endswith, re, all.",
                        )
                    )

            # 1. Field recognition check
            if field_name not in self._canonical_fields and not field_name.startswith("entity_"):
                diagnostics.append(
                    ValidationDiagnostic(
                        severity=ValidationSeverityEnum.WARNING,
                        code="UNMAPPED_FIELD_NAME",
                        field=f"detection.{sel_name}.{raw_field_expr}",
                        message=f"Field '{field_name}' is not mapped in CANONICAL_FIELD_MAP and may not match normalized events.",
                        suggested_fix="Use standard canonical field (e.g., process_name, command_line, src_ip, username).",
                    )
                )

            # 2. Broad match check (e.g. value is '*' or very short wildcard)
            if isinstance(val, str):
                cleaned = val.strip()
                if cleaned in ("*", "**", "?"):
                    diagnostics.append(
                        ValidationDiagnostic(
                            severity=ValidationSeverityEnum.WARNING,
                            code="OVERLY_PERMISSIVE_WILDCARD",
                            field=f"detection.{sel_name}.{raw_field_expr}",
                            message=f"Field '{field_name}' uses solitary wildcard '*' which will match every non-null event.",
                            suggested_fix="Specify specific command, path, or string pattern.",
                        )
                    )
            elif isinstance(val, list):
                if any(str(item).strip() in ("*", "**") for item in val):
                    diagnostics.append(
                        ValidationDiagnostic(
                            severity=ValidationSeverityEnum.WARNING,
                            code="OVERLY_PERMISSIVE_WILDCARD_LIST",
                            field=f"detection.{sel_name}.{raw_field_expr}",
                            message=f"Field '{field_name}' list contains solitary wildcard '*' matching all values.",
                            suggested_fix="Remove wildcard from value list.",
                        )
                    )

    def _build_report(
        self,
        is_valid: bool,
        rule_id: Optional[str],
        rule_title: Optional[str],
        diagnostics: List[ValidationDiagnostic],
        parsed_logsource: Dict[str, Any],
        detected_attack_ids: List[str],
        unsupported: List[str],
    ) -> RuleValidationReport:
        errors = sum(1 for d in diagnostics if d.severity == ValidationSeverityEnum.ERROR)
        warnings = sum(1 for d in diagnostics if d.severity == ValidationSeverityEnum.WARNING)
        return RuleValidationReport(
            is_valid=is_valid,
            rule_id=rule_id,
            rule_title=rule_title,
            diagnostics=diagnostics,
            error_count=errors,
            warning_count=warnings,
            parsed_logsource=parsed_logsource,
            detected_attack_ids=detected_attack_ids,
            unsupported_constructs=unsupported,
            validated_at=utc_now(),
        )


# Global default validator
sigma_validator = SigmaRuleValidator()

__all__ = ["SigmaRuleValidator", "sigma_validator"]
