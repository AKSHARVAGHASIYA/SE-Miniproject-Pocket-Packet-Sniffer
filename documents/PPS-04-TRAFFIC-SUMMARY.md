# PPS-04 traffic summary

Run the terminal dashboard from the repository root:

```powershell
.venv\Scripts\python.exe -m dashboard
```

Choose `1` to list interfaces, `2` to start a capture, `3` to refresh the
summary, `4` to stop safely, and `5` to exit. The dashboard can be viewed while
Zeek is writing logs and again after capture stops. It reads only the session's
`conn.log`; it does not require live hardware in the automated tests.

## How to interpret the summary

These are provisional definitions pending team approval:

- Protocol is the `proto` field in each Zeek `conn.log` record. Values are
  normalized to lower case. Missing, unset (`-`), empty (`(empty)`), and the
  literal `unknown` are grouped as `unknown`.
- Every complete `conn.log` record contributes one connection to the total and
  to exactly one protocol bucket. These numbers are connection counts, not
  packet counts, byte counts, or traffic volume.
- A top talker is ranked by the number of session connections involving its
  host. Both `id.orig_h` and `id.resp_h` contribute one count; a self-connection
  contributes once, not twice. Missing or empty addresses are ignored. Ties
  are ordered by host text so the display is deterministic.
- The first host in the Top talkers section is the top talker under that
  connection-count definition. This does not identify the highest byte or
  packet-volume host.

The summary keeps running totals per capture session and consumes only newly
appended records on each refresh. A separate `LogReader` owned by
`SummaryService` means a future alert consumer can read the same logs with its
own cursor.

## Dependencies and permissions

Python 3.12 is used by the current development environment; the dashboard
uses only the Python standard library and the existing project services.
Live capture additionally requires Zeek and `tcpdump` on `PATH`. On Linux,
capturing from an interface may require the appropriate OS capability or
privileged service configuration. Capture output is stored under the session
directory with owner-only permissions where the platform supports them.

## Optional authorized live-capture check

Only inspect traffic on a network you are authorized to monitor. Install Zeek
and `tcpdump`, activate the virtual environment, and run the dashboard. List
interfaces, select an interface that is up, start capture, generate a small
amount of permitted lab traffic, and refresh the summary several times. Confirm
that connection totals grow without duplicating prior records, that the first
top-talker row is understandable, and that the final summary remains available
after stopping.

This check is not automated and does not validate the SRS's five-minute novice
usability criterion, the two-second refresh target, or the Raspberry Pi packet
loss target. Those require manual usability/performance measurements on the
target environment.
