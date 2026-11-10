# PPS-08 offline module testing

The routine test suite runs offline with pytest and does not require network
interfaces, live traffic, root permissions, Zeek, tcpdump, or Raspberry Pi
hardware:

```powershell
python -m pytest -q
```

Run an individual module's tests with, for example:

```powershell
python -m pytest -q tests/test_log_reader.py
python -m pytest -q tests/test_summary_service.py
python -m pytest -q tests/test_alert_service.py
python -m pytest -q tests/test_capture_lifecycle.py
python -m pytest -q tests/test_session_index.py
```

The tests in `tests/test_capture_lifecycle.py` replace Zeek and tcpdump with
fake processes. They exercise process arguments, lifecycle handling, file
permissions where supported, and PPS-07 indexing without starting either
program. The other service tests create isolated session directories under
pytest's temporary directory.

## Synthetic fixtures

`tests/fixtures/zeek/conn.log` and `tests/fixtures/zeek/notice.log` are small,
hand-authored Zeek ASCII-format examples. They contain invented connection IDs
and timestamps and use the documentation-only IPv4 ranges TEST-NET-1
(`192.0.2.0/24`), TEST-NET-2 (`198.51.100.0/24`), and TEST-NET-3
(`203.0.113.0/24`). They are synthetic resulting log files, not captured
traffic or PCAPs:

- `conn.log` has three completed records (two TCP, one UDP), including
  repeated endpoints for deterministic summary/talker aggregation.
- `notice.log` has one supported example of each configured scan notice and
  one unsupported notice, for alert mapping, priority, and filtering tests.

The log reader, summary, alert, and capture/index integration tests copy these
fixtures into temporary session directories. The existing independent tests
also continue to cover malformed and partial lines, truncation, session
isolation, incremental reads, disabled alerts, storage errors, and dashboard
rendering.

## Interactive offline dashboard demo

The dashboard can be shown without network access, Zeek, tcpdump, or elevated
permissions using the synthetic fixtures:

```powershell
python demo.py
```

Choose option 1 to list the synthetic interface, option 2 to start a session
using `demo0`, option 3 to show the traffic summary, option 5 to enable alerting,
and option 6 to show the supported scan alerts. Choose option 4 to stop the
simulated session and option 7 to exit. The demo displays an offline-only
warning and does not capture packets. Its temporary session files are removed
when the program exits.

## Optional PCAP replay

No PCAP fixture is included, and the automated tests do not invoke Zeek replay.
If the team has an authorized, benign PCAP and wants to produce replay logs
manually, install Zeek and the `ncsa/bro-simple-scan` package referenced by
`zeek/pps05.zeek`, then run Zeek offline from a writable output directory:

```text
zeek -r <authorized-input.pcap> -C <absolute-path-to-repository>/zeek/pps05.zeek
```

Zeek writes its logs to the current directory. The supplied offline module
tests consume the included synthetic logs; substituting replay-generated logs
for exploratory testing is manual and is not part of the automated suite.
PCAP replay, live capture, reboot persistence, and Raspberry Pi operation were
not verified as part of PPS-08.
