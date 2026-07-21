#!/usr/bin/env python3
import os
import sys
import json
import importlib
from pathlib import Path
from typing import Dict, Any, List, Optional

import subprocess
import yaml
from rich.console import Console
from rich.table import Table

console = Console()


def run_cmd(cmd: List[str]) -> int:
    console.log(f"[swis] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except Exception as e:
        console.log(f"[swis] Error running command: {e}")
        return 1


class SwisConfig:
    def __init__(self):
        self.tool = os.environ.get("SWIS_TOOL", "all")
        self.image = os.environ.get("SWIS_IMAGE", "")
        self.path = os.environ.get("SWIS_PATH", ".")
        self.iac_path = os.environ.get("SWIS_IAC_PATH", ".")
        self.profile = os.environ.get("SWIS_PROFILE", "balanced")
        self.output = os.environ.get("SWIS_OUTPUT", "table")
        self.sbom_format = os.environ.get("SWIS_SBOM_FORMAT", "spdx-json")
        self.policy_file = os.environ.get("SWIS_POLICY_FILE", "policies.yaml")
        self.plugins_dir = os.environ.get("SWIS_PLUGINS_DIR", "plugins")

        if self.profile == "strict":
            self.severity = "HIGH,CRITICAL"
            self.ignore_unfixed = False
        elif self.profile == "balanced":
            self.severity = "MEDIUM,HIGH,CRITICAL"
            self.ignore_unfixed = True
        elif self.profile == "lenient":
            self.severity = "LOW,MEDIUM,HIGH,CRITICAL"
            self.ignore_unfixed = True
        else:
            raise ValueError(f"Unknown profile: {self.profile}")


class ToolResult:
    def __init__(self, name: str, exit_code: int, raw_output: Optional[str] = None, parsed: Optional[Any] = None):
        self.name = name
        self.exit_code = exit_code
        self.raw_output = raw_output
        self.parsed = parsed or {}


class SwisToolRunner:
    def __init__(self, config: SwisConfig):
        self.config = config

    def _output_flag(self) -> List[str]:
        if self.config.output == "json":
            return ["--format", "json"]
        if self.config.output == "sarif":
            return ["--format", "sarif"]
        return []

    def trivy_image(self) -> ToolResult:
        cmd = [
            "trivy", "image",
            "--severity", self.config.severity,
            "--exit-code", "1",
        ] + self._output_flag()

        if self.config.ignore_unfixed:
            cmd.append("--ignore-unfixed")

        cmd.append(self.config.image)
        code = run_cmd(cmd)
        return ToolResult("trivy_image", code)

    def trivy_fs(self) -> ToolResult:
        cmd = [
            "trivy", "fs",
            "--severity", self.config.severity,
            "--exit-code", "1",
        ] + self._output_flag()

        if self.config.ignore_unfixed:
            cmd.append("--ignore-unfixed")

        cmd.append(self.config.path)
        code = run_cmd(cmd)
        return ToolResult("trivy_fs", code)

    def grype_image(self) -> ToolResult:
        fail_level = self.config.severity.split(",")[0].lower()
        cmd = ["grype", self.config.image, "--fail-on", fail_level] + self._output_flag()
        code = run_cmd(cmd)
        return ToolResult("grype_image", code)

    def kics_scan(self) -> ToolResult:
        cmd = ["kics", "scan", "-p", self.config.iac_path, "--no-progress"]
        if self.config.output == "json":
            cmd += ["--report-formats", "json"]
        elif self.config.output == "sarif":
            cmd += ["--report-formats", "sarif"]
        code = run_cmd(cmd)
        return ToolResult("kics_scan", code)

    def sbom(self) -> ToolResult:
        if not self.config.image:
            console.log("[swis] SWIS_IMAGE required for SBOM")
            return ToolResult("sbom", 1)
        cmd = ["syft", self.config.image, "-o", self.config.sbom_format]
        code = run_cmd(cmd)
        return ToolResult("sbom", code)


class PolicyEngine:
    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.policies = self._load_policies()

    def _load_policies(self) -> Dict[str, Any]:
        path = Path(self.policy_path)
        if not path.exists():
            console.log(f"[swis] Policy file not found: {path}, skipping policy enforcement")
            return {}
        with path.open() as f:
            return yaml.safe_load(f) or {}

    def evaluate(self, results: List[ToolResult]) -> bool:
        # Simple example: deny if any tool exit_code != 0
        deny_on_failure = self.policies.get("deny_on_failure", True)
        if deny_on_failure:
            for r in results:
                if r.exit_code != 0:
                    console.log(f"[policy] Deny: {r.name} failed with exit code {r.exit_code}")
                    return False
        return True


class PluginManager:
    def __init__(self, plugins_dir: str):
        self.plugins_dir = plugins_dir
        self.plugins = self._load_plugins()

    def _load_plugins(self) -> List[Any]:
        plugins = []
        base = Path(self.plugins_dir)
        if not base.exists():
            return plugins
        for py in base.glob("*.py"):
            if py.name == "__init__.py":
                continue
            module_name = f"{base.name}.{py.stem}"
            try:
                module = importlib.import_module(module_name)
                if hasattr(module, "run_plugin"):
                    plugins.append(module)
            except Exception as e:
                console.log(f"[swis] Failed to load plugin {module_name}: {e}")
        return plugins

    def run_plugins(self, results: List[ToolResult]) -> None:
        for plugin in self.plugins:
            try:
                plugin.run_plugin(results)
            except Exception as e:
                console.log(f"[swis] Plugin error in {plugin.__name__}: {e}")


class SwisRunner:
    def __init__(self, config: SwisConfig):
        self.config = config
        self.tools = SwisToolRunner(config)
        self.policy = PolicyEngine(config.policy_file)
        self.plugins = PluginManager(config.plugins_dir)

    def run(self) -> int:
        results: List[ToolResult] = []

        if self.config.tool == "trivy":
            results.append(self.tools.trivy_image() if self.config.image else self.tools.trivy_fs())
        elif self.config.tool == "grype":
            results.append(self.tools.grype_image())
        elif self.config.tool == "kics":
            results.append(self.tools.kics_scan())
        elif self.config.tool == "sbom":
            results.append(self.tools.sbom())
        elif self.config.tool == "all":
            results.append(self.tools.trivy_image() if self.config.image else self.tools.trivy_fs())
            results.append(self.tools.grype_image())
            results.append(self.tools.kics_scan())
            results.append(self.tools.sbom())
        else:
            console.log(f"[swis] Unknown SWIS_TOOL: {self.config.tool}")
            return 1

        self._render(results)
        self.plugins.run_plugins(results)
        allowed = self.policy.evaluate(results)
        return 0 if allowed else 1

    def _render(self, results: List[ToolResult]) -> None:
        if self.config.output == "table":
            table = Table(title="Swis Results")
            table.add_column("Tool")
            table.add_column("Exit Code")
            for r in results:
                table.add_row(r.name, str(r.exit_code))
            console.print(table)
        else:
            # unified JSON-like structure
            data = {
                "profile": self.config.profile,
                "severity": self.config.severity,
                "results": [
                    {"tool": r.name, "exit_code": r.exit_code}
                    for r in results
                ],
            }
            console.print_json(data=data)
