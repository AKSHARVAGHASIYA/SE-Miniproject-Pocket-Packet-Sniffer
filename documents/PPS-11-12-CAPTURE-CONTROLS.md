# PPS-11 and PPS-12 capture controls

The terminal dashboard now asks for an interface, an optional maximum duration,
and an optional protocol filter when starting a capture. Leave either optional
prompt blank to retain the previous unrestricted, manual-stop behavior.

- Duration is a whole number of seconds from 1 through 86400 (24 hours).
- The only accepted filters are `tcp`, `udp`, and `icmp` (case-insensitive).
  Arbitrary tcpdump/Zeek expressions are intentionally rejected before either
  process is started.
- The accepted filter is passed as Zeek's `-f <protocol>` filter and tcpdump's
  final BPF expression. Both are launched as argument lists with `shell=False`.
  No probing, scanning, injection, or packet-generation command is used.

When a duration expires, the service interrupts tcpdump and Zeek, preserves the
existing PCAP and Zeek output, restricts the session files, and writes the
existing PPS-07 session-index record. Manual stops use the same finalization
path.

## Disconnect and process monitoring

While a capture runs, a daemon monitor checks once per second for:

- removal of the selected interface from OS interface enumeration;
- Linux sysfs carrier loss (`/sys/class/net/<interface>/carrier`); and
- unexpected Zeek or tcpdump exit.

An automatic-stop warning is delivered to the dashboard before process cleanup,
so normal terminal output is not delayed by the shutdown time. The monitor does
not send packets or alter the monitored network.

The carrier attribute is Linux-specific. On platforms without it, or when the
attribute cannot be read, link state is treated as unknown rather than as a
disconnect. Interface removal, administrative down state where available, and
process health are still monitored. Routine tests use fake processes and
controlled monitor calls; they do not verify a physical unplug, a real PCAP,
or five-second hardware timing.

If finalizing or indexing fails, the error is surfaced through the dashboard
and `CaptureService.last_error`; the stopped session remains available to retry
`stop_capture`, preserving PPS-07 retry behavior.

## Optional authorized live check

Only on a Linux system where you are authorized to observe the selected
network, with Zeek and tcpdump installed and sufficient capture privileges:

1. Start `python dashboard.py`, choose an up interface, set a small duration
   (for example `10`), and select `tcp`.
2. Inspect the retained session PCAP with `tcpdump -r <capture.pcap>` and check
   Zeek logs and `index.json` after automatic stopping.
3. If authorized and safe, disconnect the monitored link and confirm the
   dashboard warning appears. Do not generate probes, scans, or injected
   packets for this check.

This repository does not claim that these live checks have been performed.
