# PPS-02 manual verification

This optional test requires a Linux host, Zeek, tcpdump/libpcap, and permission
to capture on the selected interface (for example, running with appropriate
Linux capabilities or elevated privileges). Use only an interface and traffic
you are authorized to monitor.

From the repository root, start `sudo python3`, then paste the following,
replacing `eth0` with an available, up interface:

```python
from services.capture_service import CaptureService

service = CaptureService()
started = service.start_capture("eth0")
if started.status.name != "OK":
    raise RuntimeError(started.detail)

session = started.value
print(f"Capturing to {session.pcap_path}")
print(f"Zeek logs: {session.zeek_directory}")
try:
    input("Generate authorized test traffic, then press Enter to stop: ")
finally:
    status = service.stop_capture(session.session_id)
    print(f"Capture stopped: {status.name}")
```

After stopping, inspect `capture.pcap` with Wireshark or `tcpdump -r`, and
confirm that the Zeek directory contains logs (for example, `conn.log` when
connection traffic was observed). The service starts Zeek with
`zeek -i <interface> -C` for live analysis, alongside `tcpdump -U -n -i
<interface> -w <session>/capture.pcap` for packet-buffered PCAP writing. They
are separate live readers of the selected interface; the PCAP and Zeek logs
are not produced by passing a PCAP stream between the programs. Because they
capture independently, packet drops can cause their observed traffic to differ
on a busy interface.

The command forms follow the [Zeek Quick Start Guide](https://docs.zeek.org/en/current/quickstart.html)
and the [tcpdump manual](https://www.tcpdump.org/manpages/tcpdump.1.html).
