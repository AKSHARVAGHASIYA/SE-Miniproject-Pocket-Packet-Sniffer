from demo import run_demo


def test_offline_demo_shows_synthetic_summary_and_alerts(capsys):
    answers = iter(["1", "2", "demo0", "3", "5", "6", "4", "7"])

    run_demo(input_fn=lambda _: next(answers))

    output = capsys.readouterr().out
    assert "OFFLINE DEMO: synthetic fixture data only; no packets are captured." in output
    assert "Available interfaces: demo0" in output
    assert "Total connections: 3" in output
    assert "tcp: 2" in output
    assert "udp: 1" in output
    assert "Supported alerts (3)" in output
    assert "Capture stopped safely." in output
