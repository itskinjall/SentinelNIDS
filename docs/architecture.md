# Architecture

**Why Suricata, not only Wireshark?** Wireshark/tshark show packets to a human after the fact. Suricata is a continuously running IDS: it applies rules, tracks flows, parses protocols (DNS, HTTP, TLS) and emits structured **EVE JSON** events that software can consume. SentinelNIDS uses Suricata for detection and tshark/tcpdump only for packet-level evidence.

## Data flow
1. **Suricata** reads packets from `veth-sentinel` (AF_PACKET), evaluates `rules/local.rules`, and appends one JSON object per line to `eve.json` (`alert`, `dns`, `http`, `tls`, `flow`, `anomaly`, `stats`).
2. **parser.py** tails the file: stores byte offset + inode in `ingest_state`, only consumes complete lines (partial writes are retried), skips malformed lines, restarts from 0 on rotation/truncation. Every event is stored (needed for "related events" and traffic analytics); `alert` events also fill the `alerts` table with the severity mapped from rule priority (1 critical, 2 high, 3 medium, >=4 low).
3. **correlation.py** assigns each alert to a case (see detection-logic.md).
4. **risk_engine.py** recomputes the case's risk score and stores the factor breakdown.
5. **app.py** serves `/api/*` and the static dashboard. **reports.py** builds incident reports (Markdown/JSON/CSV). **pcap.py** links alerts to rolling PCAPs by time and extracts packets with tshark/tcpdump (argument lists, validated IPs, no shell).

## EVE JSON
Enabled in `config/suricata.yaml` under `outputs: - eve-log`. Payload/packet logging is off (privacy, size). `stats` is enabled as a heartbeat.

## When Suricata stops
No new events are produced, so nothing is detected. The backend notices: a `stats` event is expected every 8 s; if none arrives for 32 s (`STALE_AFTER_SEC`) `/api/health` returns `stale` and the dashboard shows a red "Detection may be offline" banner and a red status pill. A missing EVE file shows `no_file`. Previously stored alerts remain available.

## Database (SQLite, WAL)
`events`, `alerts`, `cases`, `notes`, `ingest_state`. Status (Open / Investigating / Resolved) lives on alerts and cases; setting a case's status updates its alerts.
