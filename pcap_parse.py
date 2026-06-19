#!/usr/bin/env python3

import argparse
import json
import pyshark


def get_layer_names(packet):
    names = []
    for layer in packet.layers:
        layer_name = getattr(layer, "layer_name", "")
        if layer_name:
            names.append(layer_name.upper())
    return names


def get_ip_and_ports(packet):
    if not hasattr(packet, "ip"):
        return None

    src_ip = packet.ip.src
    dst_ip = packet.ip.dst

    src_port = None
    dst_port = None

    if hasattr(packet, "tcp"):
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
    elif hasattr(packet, "udp"):
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)

    return src_ip, dst_ip, src_port, dst_port


def normalize_key(src_ip, src_port, dst_ip, dst_port):
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    a, b = sorted((ep1, ep2))
    return a, b


def extract_connections(pcap_file, target_ip):
    connections = {}
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)
    capture_start_time = None

    for packet in capture:
        pkt_time = float(packet.sniff_timestamp)

        if capture_start_time is None:
            capture_start_time = pkt_time

        parsed = get_ip_and_ports(packet)
        if parsed is None:
            continue

        src_ip, dst_ip, src_port, dst_port = parsed

        if target_ip not in (src_ip, dst_ip):
            continue

        rel_time = pkt_time - capture_start_time
        ep_a, ep_b = normalize_key(src_ip, src_port, dst_ip, dst_port)
        layer_names = get_layer_names(packet)

        transport_protocol = "UNKNOWN"
        if "TCP" in layer_names:
            transport_protocol = "TCP"
        elif "UDP" in layer_names:
            transport_protocol = "UDP"
        elif hasattr(packet, "ip") and hasattr(packet.ip, "proto"):
            transport_protocol = f"IP_PROTO_{packet.ip.proto}"

        key = f"{ep_a[0]}:{ep_a[1]} <-> {ep_b[0]}:{ep_b[1]} [{transport_protocol}]"

        if key not in connections:
            connections[key] = {
                "endpoint_a_ip": ep_a[0],
                "endpoint_a_port": ep_a[1],
                "endpoint_b_ip": ep_b[0],
                "endpoint_b_port": ep_b[1],
                "target_ip": target_ip,
                "packet_count": 0,
                "first_seen_relative_seconds": rel_time,
                "protocols_used": [],
                "protocol_stack_examples": []
            }

        connections[key]["packet_count"] += 1

        if rel_time < connections[key]["first_seen_relative_seconds"]:
            connections[key]["first_seen_relative_seconds"] = rel_time

        for proto in layer_names:
            if proto not in connections[key]["protocols_used"]:
                connections[key]["protocols_used"].append(proto)

        stack_string = " > ".join(layer_names)
        if stack_string and stack_string not in connections[key]["protocol_stack_examples"]:
            connections[key]["protocol_stack_examples"].append(stack_string)

    capture.close()
    return connections


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract bidirectional unique connections for a target IP from a PCAP file, including higher-layer protocols."
    )
    parser.add_argument("pcap_file", help="Path to input PCAP file")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("output_file", help="Path to output JSON file")
    return parser.parse_args()


def main():
    args = parse_args()
    connections = extract_connections(args.pcap_file, args.target_ip)

    with open(args.output_file, "w", encoding="utf-8") as f:
        json.dump(connections, f, indent=2)

    print(f"Saved {len(connections)} unique bidirectional connections to {args.output_file}")


if __name__ == "__main__":
    main()