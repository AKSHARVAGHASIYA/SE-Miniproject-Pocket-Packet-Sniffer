# PPS-13 dashboard refresh and capture-throughput validation

## Status

**PPS-13 is partially complete.** The terminal dashboard polls the active
session's incremental `SummaryService` every second and displays a new summary
when complete connection records change the totals. A complete line should
therefore appear at the next poll; incomplete lines remain pending until Zeek
terminates them with a newline. Manual refresh and automatic polling are
serialized, and refresh stops when capture ends or the dashboard exits.

The two-second refresh behavior has an automated local timing check using a
real temporary file and worker thread. This is not a Raspberry Pi performance
test and does not establish a hard real-time guarantee under load.

**Raspberry Pi 5 Mbps / at-most-1% packet-loss test: NOT PERFORMED.** A
Raspberry Pi is not currently available. Do not mark the throughput criterion
complete until the procedure below has been run and its measurements recorded.

## Automated tests

Run the refresh-focused tests and the full suite from the repository root:

```powershell
python -m pytest -q -s tests/test_dashboard_refresh.py
python -m pytest -q
```

The focused tests use temporary Zeek-format logs and exercise live refresh,
append-to-display timing, manual/automatic reads, missing logs, incomplete
lines, read errors, session replacement, and worker cleanup.

The timing check records a monotonic timestamp after a complete log line is
written and another when its connection count is displayed while capture is
still active. It asserts the observed delay is no more than two seconds. This
measures the current test machine's filesystem, Python scheduling, and test
load only; it uses synthetic local logs and a fake capture service, so it does
not validate the packet capture path or Raspberry Pi behavior.

## Future Raspberry Pi replay validation

Run this only in an authorized, isolated lab with a known benign replay file
and equipment capable of observing both the sent and captured packets.

1. Prepare an authorized replay PCAP containing a known number of packets with
   unique sequence identifiers. Use a separate replay host and, where
   practical, a receiving host or switch mirror so the packets delivered on
   the test link can be counted independently of the Pi's capture.
2. Record the Pi model, OS, Python, Zeek, tcpdump, tcpreplay, link speed, and
   capture configuration. Keep unrelated traffic off the test link and run
   the dashboard with Zeek and tcpdump active.
3. Replay at a target rate of 5 Mbps, for example with:

   ```text
   tcpreplay --mbps=5 --stats=1 <authorized-replay.pcap>
   ```

   Check the installed tcpreplay version's options first. Record the
   generator's successful-send count and elapsed time. Also record
   transmit/receive byte counters from the test interface or a switch/generator
   counter. State whether Mbps is decimal and whether the measurement includes
   link-layer overhead; use the same definition in every run.
4. After capture stops, count the unique replay sequence identifiers in the
   sent traffic, in the independently observed received traffic, and in the
   Pi's resulting PCAP. Record tcpdump's captured/received/kernel-dropped
   statistics as an additional diagnostic. Do not use Zeek connection counts
   as packet counts.
5. Compute observed throughput as `8 * transmitted_bytes / elapsed_seconds /
   1,000,000` for decimal Mbps, documenting the byte-counter source. Compute
   capture loss as `100 * (sent_unique_packets - Pi_captured_unique_packets)
   / sent_unique_packets`. Investigate discrepancies against the independent
   receiver count, duplicates, and tcpdump kernel-drop count; do not silently
   count missing or duplicate packets as successful captures.
6. Repeat the run with the dashboard, Zeek, and tcpdump all enabled, and save
   the commands, raw counters, PCAP packet counts, elapsed time, calculations,
   and any environmental limitations with the test results.

The Raspberry Pi acceptance criterion passes only if the measured replay
throughput is at least 5 Mbps and the calculated packet loss is at most 1%
for the documented test run(s). Until then the criterion remains **NOT
PERFORMED**, and PPS-13 remains **partially complete**.
