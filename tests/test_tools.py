import swis.core as core
from swis.core import SwisConfig, SwisToolRunner

def test_trivy_image(monkeypatch):
    def fake_run_cmd(cmd):
        assert "trivy" in cmd[0]
        return 0
    monkeypatch.setattr(core, "run_cmd", fake_run_cmd)

    cfg = SwisConfig()
    cfg.image = "myapp:latest"
    runner = SwisToolRunner(cfg)
    result = runner.trivy_image()
    assert result.exit_code == 0
