import pytest
from swis.core import SwisConfig, SwisRunner, ToolResult
import swis.core as core

def test_run_all_tools(monkeypatch):
    def fake_run_cmd(cmd):
        return 0
    monkeypatch.setattr(core, "run_cmd", fake_run_cmd)

    cfg = SwisConfig()
    cfg.tool = "all"
    cfg.image = "testimage:latest"

    runner = SwisRunner(cfg)
    exit_code = runner.run()

    assert exit_code == 0
