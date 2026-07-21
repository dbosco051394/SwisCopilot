#!/usr/bin/env python3
import sys
from core import SwisConfig, SwisRunner

def main() -> int:
    try:
        config = SwisConfig()
        runner = SwisRunner(config)
        return runner.run()
    except Exception as e:
        print(f"[swis] Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
