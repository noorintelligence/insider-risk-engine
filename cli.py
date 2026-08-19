import argparse
import sys
import json
from src.generator import generate_telemetry
from src.engine import AnalyticsEngine
from src.scorer import (
    InsiderRiskScoringEngine,
    TechnicalTelemetrySignals,
    BehavioralProfile,
)


def main():
    parser = argparse.ArgumentParser(
        description="Privacy-First Insider Threat Detection & Risk Scoring Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Command: generate
    gen_parser = subparsers.add_parser(
        "generate", help="Generate synthetic multi-source logs with embedded kill chains"
    )
    gen_parser.add_argument(
        "--count", type=int, default=10000, help="Number of baseline events (default: 10000)"
    )
    gen_parser.add_argument(
        "--out", type=str, default="telemetry.jsonl", help="Output file path (default: telemetry.jsonl)"
    )

    # 2. Command: analyze
    analyze_parser = subparsers.add_parser(
        "analyze", help="Ingest logs into DuckDB and execute detection correlation"
    )
    analyze_parser.add_argument(
        "--file", type=str, default="telemetry.jsonl", help="Input telemetry JSONL path"
    )
    analyze_parser.add_argument(
        "--scrub", action="store_true", default=True, help="Pseudonymize PII prior to analytical triaging"
    )

    # 3. Command: score
    score_parser = subparsers.add_parser(
        "score", help="Evaluate weighted risk score for an entity given signals"
    )
    score_parser.add_argument(
        "--pseudonym", type=str, default="ANON-USER-999", help="Entity pseudonym identifier"
    )
    score_parser.add_argument(
        "--egress-mb", type=float, default=3200.0, help="Off-hours cloud egress volume in MB"
    )
    score_parser.add_argument(
        "--priv-esc", action="store_true", help="Flag indicating privilege escalation detected"
    )
    score_parser.add_argument(
        "--usb-staging", action="store_true", help="Flag indicating USB staging detected"
    )
    score_parser.add_argument(
        "--scripted-ua", action="store_true", help="Flag indicating scripted User-Agent used"
    )
    score_parser.add_argument(
        "--resignation", action="store_true", help="HR indicator: active resignation notice"
    )
    score_parser.add_argument(
        "--pip", action="store_true", help="HR indicator: active Performance Improvement Plan"
    )
    score_parser.add_argument(
        "--flight-risk", type=float, default=0.85, help="Behavioral flight risk score (0.0 - 1.0)"
    )
    score_parser.add_argument(
        "--blast-radius",
        type=str,
        default="TIER_1",
        choices=["TIER_1", "TIER_2", "TIER_3"],
        help="Asset sensitivity tier (TIER_1: Prod/Keys, TIER_2: Financial, TIER_3: Standard)",
    )

    args = parser.parse_args()

    if args.command == "generate":
        print(f"[*] Generating {args.count} baseline events + embedded insider threat patterns...")
        generate_telemetry(count=args.count, out_file=args.out)
        print(f"[+] Successfully wrote {args.out}")

    elif args.command == "analyze":
        print(f"[*] Ingesting {args.file} (Privacy Scrubbing: {args.scrub})...")
        engine = AnalyticsEngine(log_path=args.file, scrub_pii=args.scrub)
        engine.run_all_detections()

    elif args.command == "score":
        scorer = InsiderRiskScoringEngine()
        signals = TechnicalTelemetrySignals(
            off_hours_egress_mb=args.egress_mb,
            privilege_escalation_detected=args.priv_esc,
            usb_staging_detected=args.usb_staging,
            scripted_client_used=args.scripted_ua,
        )
        behavior = BehavioralProfile(
            user_pseudonym=args.pseudonym,
            is_resignation_notice=args.resignation,
            is_on_pip=args.pip,
            flight_risk_score=args.flight_risk,
            access_blast_radius_tier=args.blast_radius,
        )
        result = scorer.evaluate_risk(signals=signals, behavior=behavior)
        print("\n=== EVALUATED RISK RESULT ===")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
