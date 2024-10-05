## DNS Tunneling Server

This DNS tunneling server leverages the DNS protocol to bypass network restrictions by encoding data into DNS queries and responses. The server supports two primary functionalities:
- File Transfer: Allows files to be transferred over DNS by encoding them into base32 and sending them as DNS TXT records. This includes the ability to split large files into multiple windows.
- Proxy: Operates as a DNS-based proxy, handling HTTP(S) traffic by intercepting browser requests and forwarding them through DNS queries. It supports SOCKS5-like tunneling and base32 encoding for secure data transmission.

Key Features:
- UDP DNS server
- Cloudflare DNS as a forwarder for regular queries
- Multi-threaded request handling
- File transfer and proxy functionalities via custom domain suffixes
- Efficient packet splitting and encoding for DNS payloads
This setup can be useful for bypassing restrictive networks while maintaining a lightweight and extensible solution.

## DNS Tunnel Proxy Client
A robust and efficient proxy client leveraging DNS tunneling to transmit data securely and bypass traditional network restrictions. This tool encapsulates traffic within DNS queries and responses, making it ideal for scenarios where direct internet access is blocked or restricted. The client features a SOCKS5 proxy implementation, seamless connection handling, and optimized DNS query management to ensure reliable data transmission over limited network environments.
Key features:
- DNS-based tunneling for bypassing restricted networks
- SOCKS5 proxy support for enhanced privacy
- Threaded handling for simultaneous data forwarding between client and remote server
- Base32 encoding to efficiently transmit data over DNS queries
- Reliable DNS request/response management for stable communication
