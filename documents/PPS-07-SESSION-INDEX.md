# PPS-07 local session index

Completed capture sessions are indexed by `SessionIndex`, which is owned by
`CaptureService`. The default storage location is:

```text
~/.local/share/pocket-packet-sniffer/sessions/index.json
```

Each session remains in its existing `<session-root>/<session-id>/` directory.
The version-1 JSON index stores:

- `session_id` and `interface_name`
- `started_at` and `ended_at` as timezone-aware ISO 8601 timestamps (UTC for
  sessions created by the capture service)
- Absolute `pcap_path` and `zeek_directory` paths
- `zeek_log_paths`, containing the paths to Zeek log files present when capture
  stops

The schema has a top-level `version` field so a later incompatible schema can
be handled explicitly. A missing index represents an empty history. Empty,
malformed, unsupported, or unreadable indexes return an error rather than an
empty successful result. `CaptureService.list_completed_sessions()` reads the
index in a newly created service instance. Index writes use a private
same-directory temporary file, flush it, and atomically replace `index.json`;
Linux also syncs the containing directory. Repeated indexing of a session ID
does not add another entry.

On Linux/POSIX, the session root and session directories are set to mode
`0700`, and the index, PCAP, and session files are set to `0600`. The index is
created with owner-only permissions before it is renamed into place. Other
platforms receive the available `chmod` protections, but Windows ACLs and
other platform-specific access controls are not guaranteed by these mode
bits. Keep the storage directory on a local, persistent filesystem with
appropriate user access controls.

No captured data is uploaded or sent to an external service. The index and
capture artifacts are read and written locally.

## Verify persistence

After stopping a capture, inspect the index or load it from a fresh service:

```python
from services.capture_service import CaptureService
from core.types import Status

result = CaptureService().list_completed_sessions()
if result.status is not Status.OK:
    raise RuntimeError(result.detail)
for session in result.value:
    print(session.session_id, session.pcap_path, session.zeek_log_paths)
```

The default location is under the current user's home directory, so the index
and session directories remain available when the application process is
restarted. An optional manual check is to stop a capture, restart the
application (or reboot the device), then run the snippet above and verify the
paths still point to the retained files. Automated tests use temporary
directories and mocked capture processes; they do not perform a real reboot or
live capture.

If stopping reports `IO_ERROR` or `PERMISSION_ERROR`, `CaptureService.last_error`
contains the persistence or file-permission detail. A session whose indexing
failed remains available for a later `stop_capture(session_id)` retry. This
change adds the index only; browsing and exporting sessions remain out of
scope for PPS-14 and PPS-15.
