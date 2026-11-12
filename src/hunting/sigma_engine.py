"""In-process Sigma YAML detection engine for normalized EVTX events."""

import json
import os
import re
from typing import Any, Dict, List
import yaml


class SigmaRule:
    """Represents a parsed Sigma YAML detection rule."""

    def __init__(self, rule_dict: Dict[str, Any], file_path: str):
        self.id = rule_dict.get("id", os.path.basename(file_path))
        self.title = rule_dict.get("title", "Untitled Rule")
        self.level = rule_dict.get("level", "medium")
        self.description = rule_dict.get("description", "")
        self.tags = rule_dict.get("tags", [])
        self.logsource = rule_dict.get("logsource", {})
        self.detection = rule_dict.get("detection", {})
        self.condition = str(self.detection.get("condition", ""))

    def matches_logsource(self, event: Dict[str, Any]) -> bool:
        """Fast pre-filter checking if the event belongs to the rule's target logsource."""
        product = self.logsource.get("product", "").lower()
        if product and product != "windows":
            return False

        service = self.logsource.get("service", "").lower()
        if not service:
            return True

        channel = (event.get("channel") or "").lower()
        category = (event.get("category") or "").lower()
        source_file = (event.get("source_file") or "").lower()

        service_map = {
            "security": "security" in channel or "security" in source_file,
            "sysmon": "sysmon" in channel or "sysmon" in source_file,
            "powershell": "powershell" in channel or "powershell" in source_file,
            "system": "system" in channel or "system" in source_file,
            "application": "application" in channel or "application" in source_file,
            "taskscheduler": "taskscheduler" in channel or "taskscheduler" in source_file,
            "wmi": "wmi" in channel or "wmi" in source_file,
            "dns-server": "dns" in channel or "dns" in source_file,
        }
        return service_map.get(service, service in channel or service in category)


class SigmaEngine:
    """Loads Sigma YAML rules and evaluates normalized EVTX records against them."""

    FIELD_MAP = {
        "EventID": "event_id",
        "Computer": "computer",
        "Channel": "channel",
        "Image": "process_name",
        "NewProcessName": "process_name",
        "ParentImage": "parent_process",
        "ParentProcessName": "parent_process",
        "CommandLine": "command_line",
        "ProcessCommandLine": "command_line",
        "ScriptBlockText": "command_line",
        "User": "user",
        "SubjectUserName": "user",
        "TargetUserName": "target_user",
        "IpAddress": "source_ip",
        "SourceIp": "source_ip",
        "DestinationIp": "destination_ip",
        "LogonId": "logon_id",
        "TargetLogonId": "logon_id",
        "LogonGuid": "logon_guid",
    }

    def __init__(self, rules_dir: str):
        self.rules: List[SigmaRule] = []
        if rules_dir and os.path.isdir(rules_dir):
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str) -> None:
        """Recursively loads all .yml / .yaml Sigma rules from a directory."""
        for root, _, files in os.walk(rules_dir):
            for fname in files:
                if fname.lower().endswith((".yml", ".yaml")):
                    full_path = os.path.join(root, fname)
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            for doc in yaml.safe_load_all(f):
                                if isinstance(doc, dict) and "detection" in doc:
                                    self.rules.append(SigmaRule(doc, full_path))
                    except Exception:
                        continue

    def _extract_field_value(self, event: Dict[str, Any], sigma_field: str) -> Any:
        """Retrieves field value from normalized schema first, falling back to raw_data."""
        norm_key = self.FIELD_MAP.get(sigma_field)
        if norm_key and event.get(norm_key) is not None:
            return event[norm_key]

        raw_data = event.get("raw_data", {})
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                raw_data = {}

        if sigma_field in raw_data:
            return raw_data[sigma_field]

        user_data = event.get("user_data", {})
        return user_data.get(sigma_field)

    @staticmethod
    def _match_single_value(actual: Any, expected: Any, modifiers: List[str]) -> bool:
        """Evaluates a single expected value against actual event data using Sigma modifiers."""
        if actual is None:
            return expected is None

        if isinstance(expected, int) and not modifiers:
            try:
                return int(actual) == expected
            except (ValueError, TypeError):
                return False

        actual_str = str(actual)
        expected_str = str(expected)

        if "re" in modifiers:
            return bool(re.search(expected_str, actual_str, re.IGNORECASE))

        actual_cmp = actual_str if "cased" in modifiers else actual_str.lower()
        expected_cmp = expected_str if "cased" in modifiers else expected_str.lower()

        if "contains" in modifiers:
            return expected_cmp in actual_cmp
        if "startswith" in modifiers:
            return actual_cmp.startswith(expected_cmp)
        if "endswith" in modifiers:
            return actual_cmp.endswith(expected_cmp)

        if "*" in expected_cmp or "?" in expected_cmp:
            regex_pattern = "^" + re.escape(expected_cmp).replace(r"\*", ".*").replace(r"\?", ".") + "$"
            return bool(re.match(regex_pattern, actual_cmp, re.DOTALL))

        return actual_cmp == expected_cmp

    def _evaluate_field_expr(self, event: Dict[str, Any], field_key: str, expected_val: Any) -> bool:
        """Evaluates a field key with optional pipe modifiers (e.g., CommandLine|contains|all)."""
        parts = field_key.split("|")
        base_field = parts[0]
        modifiers = parts[1:]

        actual_val = self._extract_field_value(event, base_field)

        if isinstance(expected_val, list):
            if "all" in modifiers:
                return all(self._match_single_value(actual_val, item, modifiers) for item in expected_val)
            return any(self._match_single_value(actual_val, item, modifiers) for item in expected_val)

        return self._match_single_value(actual_val, expected_val, modifiers)

    def _evaluate_selection(self, event: Dict[str, Any], selection_block: Any) -> bool:
        """Evaluates a Sigma selection dictionary or list of dictionaries."""
        if isinstance(selection_block, dict):
            return all(
                self._evaluate_field_expr(event, k, v)
                for k, v in selection_block.items()
            )
        if isinstance(selection_block, list):
            return any(
                self._evaluate_selection(event, item)
                for item in selection_block
            )
        return False

    def _evaluate_condition(self, condition: str, results: Dict[str, bool]) -> bool:
        """Evaluates Sigma boolean condition strings (e.g. 'selection and not filter')."""
        expr = condition

        quantifier_pattern = re.compile(r"(1|all)\s+of\s+([a-zA-Z0-9_*]+)")

        def replace_quantifier(match: re.Match) -> str:
            quant, pattern = match.group(1), match.group(2)
            if pattern == "them":
                matched_keys = list(results.keys())
            else:
                prefix = pattern.rstrip("*")
                matched_keys = [k for k in results if k.startswith(prefix)]
            if not matched_keys:
                return "False"
            op = any if quant == "1" else all
            return str(op(results[k] for k in matched_keys))

        expr = quantifier_pattern.sub(replace_quantifier, expr)

        for name in sorted(results.keys(), key=len, reverse=True):
            expr = re.sub(rf"{re.escape(name)}", str(results[name]), expr)

        safe_tokens = re.sub(r"(True|False|and|or|not)|[() ]", "", expr)
        if safe_tokens.strip():
            return False

        try:
            return bool(eval(expr, {"__builtins__": None}, {}))
        except Exception:
            return False

    def scan_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluates a single normalized event against all loaded Sigma rules."""
        hits = []
        for rule in self.rules:
            if not rule.matches_logsource(event):
                continue

            selection_results: Dict[str, bool] = {}
            for key, block in rule.detection.items():
                if key == "condition":
                    continue
                selection_results[key] = self._evaluate_selection(event, block)

            if self._evaluate_condition(rule.condition, selection_results):
                hits.append({
                    "timestamp": event.get("timestamp"),
                    "rule_id": rule.id,
                    "rule_title": rule.title,
                    "severity": rule.level,
                    "mitre_tags": [t for t in rule.tags if t.startswith("attack.")],
                    "computer": event.get("computer"),
                    "event_id": event.get("event_id"),
                    "summary": event.get("summary"),
                })
        return hits
