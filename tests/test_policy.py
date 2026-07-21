from core import PolicyEngine, ToolResult

def test_policy_deny():
    engine = PolicyEngine("tests/fixtures/policies_deny.yaml")
    results = [ToolResult("trivy", 1)]
    assert engine.evaluate(results) is False

def test_policy_allow():
    engine = PolicyEngine("tests/fixtures/policies_allow.yaml")
    results = [ToolResult("trivy", 0)]
    assert engine.evaluate(results) is True
