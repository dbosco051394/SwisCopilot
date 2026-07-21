from swis.core import SwisConfig

def test_strict_profile():
    cfg = SwisConfig()
    cfg.profile = "strict"
    cfg.__init__()
    assert cfg.severity == "HIGH,CRITICAL"
    assert cfg.ignore_unfixed is False
