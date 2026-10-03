"""
main.py
Convenience entry point. Run with:
    python main.py sample_logs/access.log
"""

from __future__ import annotations

import sys

from ids import IntrusionDetectionSystem, IDSConfig
from alerter import Alerter


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python main.py <path-to-access.log>")
        return 1
    log_path = sys.argv[1]
    alerter = Alerter()
    ids = IntrusionDetectionSystem(config=IDSConfig(anomaly_score_threshold=60), alerter=alerter)
    print(f"[+] Analyzing {log_path}...")
    ids.process_file(log_path)
    print()
    print(alerter.format_report())
    return 0


if __name__ == "__main__":
    sys.exit(main())