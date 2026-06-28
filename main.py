from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

from ai_explainer import AIProviderConfig, ai_explain
from detector import analyze_email
from ioc.extractor import extract_iocs
from parser.email_parser import EmailData, parse_email
from reporter import generate_case_directory, generate_mitre_navigator_layer, generate_report
from whitelist import WhitelistConfig, get_config


def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=level, format=fmt, handlers=handlers)


def analyze_file(
    file_path: Path,
    case_dir: Path,
    no_ai: bool = False,
    ai_config: Optional[AIProviderConfig] = None,
    no_mitre: bool = False,
) -> Dict[str, Any]:
    logger.info("Analyzing file: %s", file_path)
    try:
        email_data: EmailData = parse_email(file_path)
    except Exception as exc:
        logger.error("Failed to parse %s: %s", file_path, exc)
        return {"file": str(file_path), "error": str(exc)}

    headers_str = "\n".join(f"{k}: {v}" for k, v in email_data.headers.items())
    combined_text = headers_str + "\n" + email_data.body_text + "\n" + email_data.body_html
    for url in email_data.urls_from_html:
        combined_text += "\n" + url

    iocs = extract_iocs(combined_text)

    extracted_data = {
        "headers": headers_str,
        "urls": iocs["urls"],
        "domains": iocs["domains"],
        "ips": iocs["ips"],
        "emails": iocs["emails"],
        "body_text": email_data.body_text,
        "body_html": email_data.body_html,
        "forms": email_data.forms,
    }

    analysis = analyze_email(extracted_data)

    report_path = generate_report(email_data.__dict__, iocs, analysis, email_path=file_path, case_dir=case_dir)

    if not no_ai:
        ai_explain(extracted_data, analysis, case_dir=case_dir, config=ai_config)

    if not no_mitre:
        mitre_path = case_dir / f"{case_dir.name}_mitre_layer.json"
        generate_mitre_navigator_layer(analysis, case_dir.name, mitre_path)

    return {
        "file": str(file_path),
        "case_dir": str(case_dir),
        "verdict": analysis["verdict"],
        "score": analysis["score"],
        "confidence": _confidence(analysis["score"]),
        "reasons": analysis["reasons"],
        "report": report_path,
        "iocs": iocs,
    }


def _confidence(score: int) -> str:
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def batch_analyze(directory: Path, output_dir: Path, no_ai: bool, ai_config: Optional[AIProviderConfig], no_mitre: bool) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    eml_files = sorted(directory.rglob("*.eml"))
    if not eml_files:
        logger.warning("No .eml files found in %s", directory)
        return results

    logger.info("Found %d .eml files in %s", len(eml_files), directory)
    for eml_path in eml_files:
        try:
            file_case_dir = output_dir / eml_path.stem
            result = analyze_file(eml_path, file_case_dir, no_ai=no_ai, ai_config=ai_config, no_mitre=no_mitre)
            results.append(result)
        except Exception as exc:
            logger.error("Failed to analyze %s: %s", eml_path, exc)
            results.append({"file": str(eml_path), "error": str(exc)})

    summary_path = output_dir / "batch_summary.json"
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump({"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "results": results}, fh, indent=2)
    logger.info("Batch summary written to %s", summary_path)
    return results


def monitor_directory(directory: Path, output_dir: Path, no_ai: bool, ai_config: Optional[AIProviderConfig], no_mitre: bool) -> None:
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        logger.error("watchdog is required for monitoring mode. Install with: pip install watchdog")
        sys.exit(1)

    class Handler(FileSystemEventHandler):
        def on_created(self, event):  # type: ignore[override]
            if not event.is_directory and event.src_path.endswith(".eml"):
                logger.info("New file detected: %s", event.src_path)
                try:
                    case_dir = output_dir / Path(event.src_path).stem
                    analyze_file(Path(event.src_path), case_dir, no_ai=no_ai, ai_config=ai_config, no_mitre=no_mitre)
                except Exception as exc:
                    logger.error("Failed to analyze %s: %s", event.src_path, exc)

    event_handler = Handler()
    observer = Observer()
    observer.schedule(event_handler, str(directory), recursive=False)
    observer.start()
    logger.info("Monitoring directory %s for new .eml files. Press Ctrl+C to stop.", directory)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phish-investigator",
        description="Automated phishing email investigation tool for SOC teams",
    )
    parser.add_argument("input", type=Path, help="Path to .eml file or directory of .eml files")
    parser.add_argument("-o", "--output", type=Path, default=Path("reports"), help="Output directory (default: reports)")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI explanation generation")
    parser.add_argument("--ai-provider", choices=["ollama", "openai", "anthropic"], default="ollama", help="AI provider (default: ollama)")
    parser.add_argument("--ai-model", default="llama3.2", help="AI model name (default: llama3.2)")
    parser.add_argument("--ai-api-key", default=None, help="API key for OpenAI/Anthropic")
    parser.add_argument("--ai-base-url", default="http://127.0.0.1:11434", help="Base URL for Ollama (default: http://127.0.0.1:11434)")
    parser.add_argument("--no-mitre", action="store_true", help="Skip MITRE ATT&CK Navigator layer generation")
    parser.add_argument("--whitelist", type=Path, default=None, help="Path to custom whitelist file")
    parser.add_argument("--whitelist-mode", choices=["exact", "subdomain"], default="subdomain", help="Whitelist matching mode (default: subdomain)")
    parser.add_argument("--format", choices=["text", "json", "both"], default="both", help="Report format (default: both)")
    parser.add_argument("--monitor", action="store_true", help="Monitor directory for new .eml files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--log-file", type=Path, default=None, help="Write logs to file")

    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose, log_file=args.log_file)
    logger.info("Starting phishing investigator")

    if args.whitelist:
        from whitelist import WhitelistConfig, MatcherMode, set_config
        mode = MatcherMode.EXACT if args.whitelist_mode == "exact" else MatcherMode.SUBDOMAIN
        set_config(WhitelistConfig(path=args.whitelist, mode=mode))
        logger.info("Custom whitelist loaded from %s (mode=%s)", args.whitelist, args.whitelist_mode)

    args.output.mkdir(parents=True, exist_ok=True)

    ai_config = AIProviderConfig(
        provider=args.ai_provider,
        api_key=args.ai_api_key,
        model=args.ai_model,
        base_url=args.ai_base_url,
    )

    if args.monitor:
        if not args.input.is_dir():
            logger.error("Monitor mode requires a directory input")
            return 1
        monitor_directory(args.input, args.output, args.no_ai, ai_config, args.no_mitre)
        return 0

    if args.input.is_dir():
        results = batch_analyze(args.input, args.output, args.no_ai, ai_config, args.no_mitre)
        phish_count = sum(1 for r in results if r.get("verdict") == "PHISHING")
        susp_count = sum(1 for r in results if r.get("verdict") == "SUSPICIOUS")
        logger.info("Batch complete: %d files analyzed, %d PHISHING, %d SUSPICIOUS", len(results), phish_count, susp_count)
        return 0

    if not args.input.exists():
        logger.error("Input file not found: %s", args.input)
        return 1

    try:
        case_dir = generate_case_directory(args.input, {})
        result = analyze_file(args.input, case_dir, no_ai=args.no_ai, ai_config=ai_config, no_mitre=args.no_mitre)

        if args.format == "json":
            print(json.dumps(result, indent=2))
        elif args.format == "text":
            with open(case_dir / f"{case_dir.name}.txt", "r", encoding="utf-8") as fh:
                print(fh.read())
        else:
            print(f"Case directory: {case_dir}")
            print(f"Verdict: {result['verdict']}")
            print(f"Score: {result['score']}")
            print(f"Confidence: {result['confidence']}")
            print(f"Report: {result['report']}")
            for reason in result["reasons"]:
                print(f"  - {reason}")
        return 0
    except Exception as exc:
        logger.error("Analysis failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
