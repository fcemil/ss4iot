#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


def load_json_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def merge_connection_entry(merged_entry, incoming_entry, source_file):
    merged_entry["packet_count"] += incoming_entry.get("packet_count", 0)

    incoming_first_seen = incoming_entry.get("first_seen_relative_seconds")
    if incoming_first_seen is not None:
        current_first_seen = merged_entry.get("first_seen_relative_seconds")
        if current_first_seen is None or incoming_first_seen < current_first_seen:
            merged_entry["first_seen_relative_seconds"] = incoming_first_seen

    existing_protocols = set(merged_entry.get("protocols_used", []))
    incoming_protocols = set(incoming_entry.get("protocols_used", []))
    merged_entry["protocols_used"] = sorted(existing_protocols | incoming_protocols)

    if "protocol_stack_examples" in incoming_entry:
        existing_stacks = set(merged_entry.get("protocol_stack_examples", []))
        incoming_stacks = set(incoming_entry.get("protocol_stack_examples", []))
        merged_entry["protocol_stack_examples"] = sorted(existing_stacks | incoming_stacks)

    if "source_files" not in merged_entry:
        merged_entry["source_files"] = []

    merged_entry["source_files"].append({
        "file": source_file.name,
        "first_seen_relative_seconds": incoming_first_seen
    })


def aggregate_folder(input_folder):
    input_path = Path(input_folder)
    json_files = sorted(input_path.glob("*.json"))

    if not json_files:
        raise FileNotFoundError(f"No JSON files found in folder: {input_folder}")

    aggregated = {}
    expected_target_ip = None

    for json_file in json_files:
        data = load_json_file(json_file)

        for conn_key, conn_value in data.items():
            target_ip = conn_value.get("target_ip")

            if expected_target_ip is None:
                expected_target_ip = target_ip
            elif target_ip != expected_target_ip:
                raise ValueError(
                    f"Target IP mismatch in {json_file.name}: "
                    f"expected {expected_target_ip}, found {target_ip}"
                )

            if conn_key not in aggregated:
                aggregated[conn_key] = {
                    "endpoint_a_ip": conn_value.get("endpoint_a_ip"),
                    "endpoint_a_port": conn_value.get("endpoint_a_port"),
                    "endpoint_b_ip": conn_value.get("endpoint_b_ip"),
                    "endpoint_b_port": conn_value.get("endpoint_b_port"),
                    "target_ip": conn_value.get("target_ip"),
                    "packet_count": 0,
                    "first_seen_relative_seconds": conn_value.get("first_seen_relative_seconds"),
                    "protocols_used": [],
                    "protocol_stack_examples": [],
                    "source_files": []
                }

            merge_connection_entry(aggregated[conn_key], conn_value, json_file)

    for entry in aggregated.values():
        entry["source_files"].sort(
            key=lambda x: (
                float("inf") if x["first_seen_relative_seconds"] is None
                else x["first_seen_relative_seconds"],
                x["file"]
            )
        )

    return aggregated


def parse_args():
    parser = argparse.ArgumentParser(
        description="Aggregate multiple connection JSON files into one merged JSON file."
    )
    parser.add_argument("input_folder", help="Folder containing JSON files to aggregate")
    parser.add_argument("output_file", help="Path to the merged output JSON file")
    return parser.parse_args()


def main():
    args = parse_args()
    aggregated = aggregate_folder(args.input_folder)

    with open(args.output_file, "w", encoding="utf-8") as f:
        json.dump(aggregated, f, indent=2)

    print(f"Saved {len(aggregated)} aggregated connections to {args.output_file}")


if __name__ == "__main__":
    main()