"""
# Network Packet Analyzer
![Project Icon](icon.png)

A Python-based network packet analyzer tool that captures and analyzes network packets.
Utilizes the `scapy` library for packet sniffing and the `psutil` library to identify active network interfaces.

## Features

- **Packet Sniffing**: Captures network packets in real-time.
- **IP Address Extraction**: Logs source and destination IP addresses.
- **Protocol Identification**: Identifies the protocol used in the packet.
- **Payload Display**: Shows the payload data of captured packets.
- **Active Interface Detection**: Automatically detects the active network interface.

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/network-packet-analyzer.git
    cd network-packet-analyzer
    ```

2. **Install dependencies:**

    ```bash
    pip install scapy psutil
    ```

## Usage

1. **Run the script:**

    ```bash
    python packet_analyzer.py
    ```

2. **View captured packets:**

   The script will display captured packet information including source IP, destination IP, protocol, and payload directly in the console.

## Example

```bash
$ python packet_analyzer.py
Starting packet sniffer...
Detected active interface: eth0
Source IP: 192.168.1.5
Destination IP: 192.168.1.10
Protocol: 6
Payload: b'Hello World'
```
## How It Works

The script performs the following steps:

    1.Detect Active Interface: Uses psutil to find an active, non-loopback network interface.
    2.Start Sniffing: Uses scapy to capture packets from the detected interface.
    3.Packet Callback: Processes each packet to extract and display IP addresses, protocol, and payload data.

Logs are displayed in real-time in the console.

## Output Examples
### Packet Details
#### Example Packet Information

```plaintext

Source IP: 192.168.1.5
Destination IP: 192.168.1.10
Protocol: 6
Payload: b'Hello World'

Source IP: 192.168.1.15
Destination IP: 192.168.1.20
Protocol: 17
Payload: b'UDP Payload Data'
```

## Contributing

Feel free to open issues or submit pull requests if you have suggestions for improvements or encounter any issues.

## License

This project is licensed under the MIT License.
