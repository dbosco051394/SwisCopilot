import pytest
from core import SwisConfig, SwisRunner, ToolResult, PolicyEngine
import os

def test_profile_strict():
    cfg = SwisConfig()
    os.environ["SWIS_PROFILE"] = "strict"
    cfg.__init__()  # re-init to apply profile
    assert cfg.severity == "HIGH,CRITICAL"
    assert cfg.ignore_unfixed is False

def test_policy_allow_all():
    engine = PolicyEngine(policy_path="tests/fixtures/policies_allow.yaml")
    results = [ToolResult("trivy", 0), ToolResult("grype", 0)]
    assert engine.evaluate(results) is True

def test_policy_deny_on_failure():
    engine = PolicyEngine(policy_path="tests/fixtures/policies_deny.yaml")
    results = [ToolResult("trivy", 0), ToolResult("grype", 1)]
    assert engine.evaluate(results) is False

def test_runner_unknown_tool(monkeypatch):
    cfg = SwisConfig()
    cfg.tool = "unknown"
    runner = SwisRunner(cfg)
    assert runner.run() == 1
