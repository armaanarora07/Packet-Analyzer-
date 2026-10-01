# Packet Analyzer — Java DPI & Network Traffic Analysis

## Overview

Packet Analyzer is a Java 17+ Deep Packet Inspection (DPI) and network traffic analysis system. The engine operates on PCAP network captures, performs layer-by-layer packet dissection across Ethernet, IPv4, TCP, and UDP protocols, tracks bidirectional conversational flows, extracts application-level metadata, enforces rule-based traffic policies, aggregates comprehensive inspection statistics, and exposes structured metrics through an embedded REST API consumed by a browser-based dashboard.

---

## Architecture

The system processes network traffic through a sequential, decoupled pipeline:

```
PCAP
  ↓
PCAP Reader
  ↓
Packet Parser
  ↓
Five-Tuple Flow Tracking
  ↓
DPI / Metadata Extraction
  ↓
Application Classification
  ↓
Rule Engine
  ↓
Statistics
  ↓
REST API
  ↓
HTML/CSS/JavaScript Dashboard
```

### Stage Responsibilities
1. **PCAP**: Source packet capture files containing raw link-layer network frames.
2. **PCAP Reader**: Ingests binary capture data, detects file-level magic numbers, handles endianness (byte ordering), and emits raw packet records.
3. **Packet Parser**: Decodes raw frame bytes sequentially into structured headers across Layer 2 (Ethernet), Layer 3 (IPv4), Layer 4 (TCP and UDP), and separates the transport payload.
4. **Five-Tuple Flow Tracking**: Computes an immutable Five-Tuple key for each packet and maps packets to bidirectional connection sessions while tracking TCP handshake and termination states.
5. **DPI / Metadata Extraction**: Inspects unencrypted transport payload bytes to extract application-level protocol attributes, including TLS Client Hello Server Name Indication (SNI), HTTP Host headers, DNS query domains, and QUIC handshake parameters.
6. **Application Classification**: Maps extracted domain and protocol metadata against known application patterns to determine the Layer-7 service (e.g., YouTube, Google, Netflix, Amazon, Apple, DNS).
7. **Rule Engine**: Evaluates configurable security rules against packet and flow attributes (Source IP, Destination Port, Application Type, and Wildcard Domains) to yield forwarding or dropping verdicts.
8. **Statistics**: Aggregates throughput volumes, packet counts, protocol breakdowns, policy dispositions, and application distribution metrics into thread-safe models.
9. **REST API**: Exposes the aggregated metrics and active flow tables as JSON via an embedded HTTP service.
10. **HTML/CSS/JavaScript Dashboard**: Visualizes traffic metrics, application distributions, policy enforcement, and searchable flow tables in a modern web UI.

---

## Phase 1 — Completed

All components in Phase 1 are fully implemented, verified, and operational.

### Packet Processing
* **PCAP Ingestion & Generation**: Binary PCAP reader and writer supporting standard capture formats.
* **Endianness Handling**: Dynamic detection and conversion of native and reversed byte ordering.
* **Ethernet Decoding**: 14-byte Ethernet II frame parsing, validating MAC addresses and EtherType (IPv4).
* **IPv4 Decoding**: IPv4 header parsing with variable header lengths (IHL), Total Length, TTL, Protocol, and 32-bit IP addresses.
* **TCP Decoding**: TCP header parsing with variable Data Offset, Sequence and Acknowledgment numbers, and control flags (SYN, ACK, FIN, RST, PSH, URG).
* **UDP Decoding**: UDP header parsing extracting 16-bit Source/Destination ports, packet length, and checksum.
* **Payload Extraction**: Clean separation of protocol payload bytes from network headers for deep inspection.

### Stateful Flow Tracking
* **Immutable Five-Tuple**: Encapsulates Source IP, Destination IP, Source Port, Destination Port, and Protocol (`FiveTuple`) with stable hash code and equality implementations.
* **Bidirectional Flow Matching**: Flow symmetry supported via `reverse()` lookup, guaranteeing that client-to-server and server-to-client packets map to the same session record.
* **Lifecycle State Tracking**: Monitors flow connection states (`NEW`, `ESTABLISHED`, `CLASSIFIED`, `BLOCKED`, `CLOSED`).
* **Flow Counters**: Tracks cumulative inbound/outbound packet counts, byte volumes, and timestamps per connection.

### Deep Packet Inspection
* **TLS Client Hello / SNI Extraction**: Parses TLS 1.2 and 1.3 records to extract the Server Name Indication (SNI) extension from cleartext handshakes.
* **HTTP Host Extraction**: Scans cleartext HTTP/1.x request payloads to extract the `Host:` header value.
* **DNS Query Extraction**: Decodes DNS question sections on port 53 to extract queried domain names.
* **QUIC Metadata Extraction**: Parses QUIC Initial packets for embedded TLS Client Hello tokens.
* **Application Classification**: Maps identified hostnames and domains to application categories (Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon, Apple, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare).
* **Payload Privacy Notice**: Cleartext metadata only is inspected; encrypted transport payloads are **not** decrypted.

### Rule-Based Traffic Enforcement
* **Source IP Filtering**: Blocks traffic originating from specific IPv4 addresses.
* **Destination Port Filtering**: Blocks traffic targeting designated TCP/UDP service ports.
* **Application Filtering**: Enforces policy drops for target application types (e.g., YouTube).
* **Wildcard Domain Filtering**: Pattern-matches domains with wildcard support (e.g., `*.tiktok.com`, `badsite.org`).
* **Verdict Enforcement**: Assigns `FORWARD` or `DROP` actions to individual packets and flows.
* **Filtered PCAP Generation**: Writes permitted (forwarded) packets into a new binary PCAP file.

### REST API
* **Embedded Server**: Built directly on the standard JDK `HttpServer` (zero external web frameworks).
* **Endpoints**:
  * `GET /api/stats`: Returns JSON containing total packets, byte volume, forwarded packets, dropped packets, drop rate percentage, TCP packets, UDP packets, active flows, top domains, and application distribution.
  * `GET /api/flows`: Returns a JSON array of active tracked flows with source/destination endpoints, protocol, application, SNI, packet count, byte volume, flow state, and policy action.
* **CORS Support**: Implements `Access-Control-Allow-Origin: *` and handles `OPTIONS` preflight requests.

### Web Dashboard
* **Architecture**: Built entirely with HTML5, CSS3, and Vanilla JavaScript; no external frameworks, UI libraries, or build bundlers.
* **API Consumption**: Uses standard browser `fetch()` to poll `/api/stats` and `/api/flows`.
* **DOM Manipulation**: Updates metrics, progress bars, and table rows dynamically via native DOM APIs.
* **Visual Components**:
  * Metric summary cards for Total Packets, Forwarded, Dropped, Active Flows, TCP, and UDP.
  * CSS percentage progress bars displaying application distribution sorted by volume.
  * Traffic & security enforcement section visualizing forwarded vs. dropped packet ratios.
  * Active flows table displaying 5-tuple endpoints, protocol badges, application, SNI, packets, bytes, state, and policy action.
  * Real-time client-side search box filtering flows by IP, application, SNI, or port.
  * Connection health status indicator, last-updated timestamp, 5-second polling cycle, manual refresh button, and network error banner.

### Verification
* **40 Automated Tests**: Complete test suite spanning unit, integration, and end-to-end scenarios with **0 failures and 0 errors**.
* **End-to-End Processing Verified**: Verified against real PCAP captures (`test_dpi.pcap`), confirming exact packet parsing (77 packets, 27 active flows, 0 drops) across CLI, REST API responses, and headless browser DOM rendering.
* **Zero External Dependencies for Core Runtime**: Uses standard JDK networking and pure Java binary parsing.

---

## Phase 2 — Ongoing

The following capabilities represent active and planned engineering enhancements:

### Concurrent Packet Processing
* **Producer-Consumer Pipeline**: Architecting decoupled packet-reading threads and worker-thread pools.
* **Thread-Safe Queues**: Bounded, non-blocking queue structures for transferring parsed packets to inspection workers.
* **Flow-Affinity Work Partitioning**: Consistent hashing of the Five-Tuple to pin packets of the same flow to dedicated worker threads, ensuring lock-free state transitions.
* **Concurrent Architecture**: Formalizing thread safety and lock-free execution across high-volume pipelines.

### Deeper DPI and Protocol Coverage
* **Expanded Application Signatures**: Broader Layer-7 protocol fingerprinting beyond common web domains.
* **Protocol Diversity**: Additional parsers for IPv6, ICMP, SCTP, and specialized industrial/enterprise protocols.
* **Resilient TLS/QUIC Handling**: Enhanced parsing of fragmented TLS records and QUIC connection migrations.
* **Edge-Case Tolerance**: Malformed packet recovery, out-of-order TCP segment handling, and overlapping retransmissions.

### Performance & Reliability
* **Throughput Benchmarking**: Systematic latency, throughput, and packet-drop benchmarking under multi-megabit workloads.
* **Memory & Profiling**: Heap allocation profiling, garbage collection overhead minimization, and object pooling.
* **Stress Testing**: Processing multi-gigabyte captures with millions of packets to validate memory footprint and connection eviction strategies.
* **Extended Test Scenarios**: Fuzz testing packet parsers against malformed and hostile payloads.

### Dashboard Evolution
* **Richer Traffic Visualizations**: Time-series bandwidth tracking and throughput trend graphs.
* **Detailed Flow Inspection**: Interactive modal views displaying TCP state transitions, sequence numbers, and packet timestamps per flow.
* **Configurable Thresholds**: Live alert thresholds for abnormal drop rates or protocol spikes.
* **Advanced Monitoring Controls**: Dynamic sorting, custom pagination, and rule configuration from the UI.

---

## Requirements

* **Java**: JDK 17 or higher
* **Build Tool**: Maven 3.8+ (or the included Maven Wrapper)

---

## Build

Navigate to the `java` directory and run the Maven Wrapper:

### Windows (PowerShell)
```powershell
cd java
.\mvnw.cmd clean test package
```

### Linux / macOS
```bash
cd java
./mvnw clean test package
```

The build compiles the project, runs all 40 tests, and generates the standalone executable JAR at:
`target/packet-analyzer.jar`

---

## Run

All commands are executed from the `java` directory.

### 1. Basic PCAP Analysis
Process a PCAP capture file and output formatted summary and classification reports to the console:
```bash
java -jar target/packet-analyzer.jar ../test_dpi.pcap
```

Limit processing to a specific number of packets:
```bash
java -jar target/packet-analyzer.jar ../test_dpi.pcap 50
```

### 2. Filtering & Rule Enforcement
Block specific applications, wildcard domains, or IP addresses and write permitted traffic to an output PCAP:
```bash
java -jar target/packet-analyzer.jar ../test_dpi.pcap filtered.pcap --block-app YouTube --block-domain "*.tiktok.com" --verbose
```

Block by source IP address:
```bash
java -jar target/packet-analyzer.jar ../test_dpi.pcap filtered.pcap --block-ip 192.168.1.50
```

Block by destination port:
```bash
java -jar target/packet-analyzer.jar ../test_dpi.pcap filtered.pcap --block-port 445
```

### 3. Start REST API & Web Dashboard
Process a PCAP capture and immediately start the embedded HTTP server:
```bash
java -jar target/packet-analyzer.jar ../test_dpi.pcap --server 8080
```

Once started, access the web dashboard in your browser:
**[http://localhost:8080/](http://localhost:8080/)**

The REST API endpoints will also be directly accessible:
* `http://localhost:8080/api/stats`
* `http://localhost:8080/api/flows`

---

## Testing

Run the full automated test suite using Maven:

```powershell
cd java
.\mvnw.cmd clean test
```

The test suite consists of **40 automated tests** covering:
* **API Endpoints (`ApiServerTest`)**: Validates HTTP status codes (`200 OK`, `204 No Content`, `404 Not Found`, `405 Method Not Allowed`), CORS response headers, JSON content types, and static dashboard asset serving.
* **JSON Serialization (`JsonUtilsTest`)**: Verifies correct formatting and character escaping of metrics, flow tables, and empty states.
* **Packet Parsing (`PacketParserTest`)**: Verifies layer-by-layer header decoding (Ethernet, IPv4, TCP flags/options, UDP) and rejection of truncated frames.
* **Stateful Flow Tracking (`ConnectionTrackerTest`, `FiveTupleTest`)**: Tests bidirectional flow hashing, key immutability, metric aggregation, and idle connection cleanup.
* **Deep Packet Inspection (`PayloadExtractorsTest`, `ProtocolAndApplicationTest`)**: Tests TLS SNI, HTTP Host, DNS question decoding, and application classification mappings.
* **Rule Enforcement (`RuleManagerTest`)**: Validates IP, port, application, and wildcard domain blocking rules and rule persistence.
* **End-to-End Pipeline (`DpiEngineEndToEndTest`)**: Executes end-to-end processing of real PCAP files, verifying packet counts, drop rates, and binary integrity of generated output PCAPs.

---

## Current Scope & Limitations

* **Single-Threaded Packet Core**: The packet processing pipeline currently runs single-threaded. HTTP API handlers serve thread-safe snapshots from the statistics service. Multi-threaded processing is part of the Phase 2 roadmap.
* **Processed Capture Scope**: The dashboard displays statistics from processed capture files held in memory. The system is not currently an enterprise multi-gigabit live-capture daemon.
* **Cleartext Protocol Inspection**: DPI features inspect cleartext protocol metadata (TLS SNI, HTTP Host, DNS queries). Encrypted application payloads are **not** decrypted.
* **Embedded Framework-Free Stack**: Built without Spring Boot, Tomcat, Netty, React, Tailwind, Bootstrap, Chart.js, or WebSockets.
* **Planned Concurrency**: Concurrency, worker-pool scaling, and throughput optimizations are scoped for Phase 2.
