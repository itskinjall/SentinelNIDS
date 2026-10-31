# Test scenarios

Run on your isolated lab only. For each: start Suricata + backend, run the command, record observed results. **Fill the "Observed" column from your own run** - these expected values are predictions until you verify them.

| # | Scenario | Command | Expected SIDs | Must NOT happen | Observed (fill in) |
|---|---|---|---|---|---|
| 1 | Port scan | `./scripts/run_scenarios.sh scan` | 9000001, 9000003, 9000002, 9000040 | - | |
| 2 | Repeated connections | `./scripts/run_scenarios.sh repeat` | 9000010 | Claiming "brute force" | |
| 3 | Suspicious DNS | `./scripts/run_scenarios.sh dns` | 9000021, 9000020, 9000022 | - | |
| 4 | Normal traffic | `./scripts/run_scenarios.sh normal` | none | **Any alert** | |

## Verification checklist
- `sudo suricata -T -c config/suricata.yaml` passes.
- `tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"'` shows alerts during 1-3.
- Dashboard: alerts show source/destination; scan alerts group into one correlated case; Scenario 4 shows events but 0 new alerts.
- Stop Suricata: banner turns red within ~32 s. Restart: it recovers.
- Export a case as MD/JSON/CSV.
- Note anything *missed* (e.g. `nmap -T1` slow scan) in docs/limitations.md.

## Backend tests already run (sample data)
Partial last line retried; malformed line skipped (1); file rotation re-read from offset 0; 9 sample alerts -> 3 cases (5 / 1 / 3 alerts), 2 correlated; normal-traffic section of the sample produced 0 alerts.
