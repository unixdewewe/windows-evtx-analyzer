"""Enterprise CLI entry point with SQLite+FTS5 indexing and Sigma threat hunting."""

import argparse
import os
from src.core.ingester import EvtxIngester
from src.core.parser import EventParser
from src.core.storage import ForensicStorage
from src.normalizers.registry import NormalizerRegistry
from src.hunting.sigma_engine import SigmaEngine
from src.engine.correlation import CorrelationEngine
from src.engine.timeline import TimelineBuilder
from src.exporters.json_exporter import JSONExporter
from src.exporters.csv_exporter import CSVExporter


def collect_evtx_files(input_path: str):
    if os.path.isfile(input_path):
        return [input_path]
    evtx_files = []
    for root, _, files in os.walk(input_path):
        for file in files:
            if file.lower().endswith(".evtx"):
                evtx_files.append(os.path.join(root, file))
    return evtx_files


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Windows Event Log (.evtx) Forensic Analyzer & Sigma Hunting Engine"
    )
    parser.add_argument("-i", "--input", help="Path to .evtx file or directory of logs")
    parser.add_argument("--db", help="Path to SQLite case database (enables WAL + FTS5 indexing)")
    parser.add_argument("--rules", default="rules", help="Directory containing YAML Sigma detection rules")
    parser.add_argument("--query", type=str, help="Full-text FTS5 query against an existing --db")
    parser.add_argument("-o", "--output", required=True, help="Output file path (.json or .csv)")
    parser.add_argument("--alerts-out", help="Optional output JSON path for Sigma rule detection alerts")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Export format")
    parser.add_argument("--event-ids", nargs="+", type=int, help="Filter by specific Event IDs")
    parser.add_argument("--keyword", type=str, help="Filter events containing a keyword")
    args = parser.parse_args()

    storage = ForensicStorage(args.db) if args.db else None
    sigma_engine = SigmaEngine(args.rules) if args.rules and os.path.isdir(args.rules) else None
    if sigma_engine:
        print(f"[*] Loaded {len(sigma_engine.rules)} Sigma detection rule(s) from '{args.rules}'.")

    all_alerts = []

    # Mode 1: Ingest EVTX files if --input is provided
    if args.input:
        registry = NormalizerRegistry()
        timeline = TimelineBuilder()
        evtx_files = collect_evtx_files(args.input)
        print(f"[*] Found {len(evtx_files)} .evtx file(s) to ingest.")

        for file_path in evtx_files:
            filename = os.path.basename(file_path)
            if os.path.getsize(file_path) == 0:
                continue

            ingester = EvtxIngester(file_path)
            batch = []
            for xml_str in ingester.iter_records():
                try:
                    raw_event = EventParser.parse_record(xml_str, source_file=filename)
                    normalizer = registry.get_normalizer(filename, raw_event)
                    norm_ev = normalizer.normalize(raw_event)
                    batch.append(norm_ev)

                    if sigma_engine:
                        hits = sigma_engine.scan_event(norm_ev)
                        if hits:
                            all_alerts.extend(hits)
                except Exception:
                    continue

            if storage:
                storage.insert_batch(batch)
            else:
                timeline.add_events(batch)

        if storage and all_alerts:
            storage.insert_alerts(all_alerts)

    # Retrieve filtered/queried events from SQLite or in-memory timeline
    if storage:
        if args.query:
            results = storage.search_fts(args.query)
        else:
            results = storage.query_events(event_ids=args.event_ids, keyword=args.keyword)
    else:
        if not args.input:
            parser.error("Either --input or an existing --db must be specified.")
        correlator = CorrelationEngine()
        sorted_events = timeline.build(event_ids=args.event_ids, keyword=args.keyword)
        results = correlator.correlate(sorted_events)

    if args.format == "csv" or args.output.lower().endswith(".csv"):
        CSVExporter.export(results, args.output)
    else:
        JSONExporter.export(results, args.output)

    print(f"[+] Exported {len(results)} event(s) to {args.output}")

    if all_alerts:
        print(f"[!] Triggered {len(all_alerts)} Sigma rule alert(s)!")
        if args.alerts_out:
            JSONExporter.export(all_alerts, args.alerts_out)
            print(f"[+] Exported Sigma alerts to {args.alerts_out}")

    if storage:
        storage.close()


if __name__ == "__main__":
    main()
