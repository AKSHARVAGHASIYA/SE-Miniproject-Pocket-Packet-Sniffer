# PPS-03 LogReader integration

`services.log_reader.LogReader` reads standard Zeek ASCII logs from the
`CaptureSession.zeek_directory` established by PPS-02.  A call to
`reader.read(session, ["conn", "notice"])` returns newly completed
`ZeekLogRecord` objects in `Result.value`.  A record includes `session_id`,
`log_name`, and a field-name-to-value mapping; Zeek's unset value becomes
`None` and its empty-field value becomes `""`.

The reader tracks byte offsets independently for each session and log.  It
does not advance past an unterminated line, and resets a cursor when it sees a
smaller file or a changed file identity (truncation or rotation).  Missing
logs are normal during a live capture because Zeek creates a log only after it
observes that kind of event; they simply yield an empty successful result.
Malformed complete rows are skipped and reported in `Result.detail`.

PPS-02 integration is only to pass its returned `CaptureSession` to the
reader—no path configuration is duplicated.  Dashboard and alert services
must each own a `LogReader` instance (or distinct reader subscriptions); a
reader cursor is consumer-local, so neither consumer consumes records for the
other.  The current PPS-02 command uses Zeek's default ASCII output.  If it is
changed to JSON or another writer, PPS-02 and PPS-03 must coordinate a parser
addition before that format is used.
