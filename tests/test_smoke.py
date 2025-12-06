from pnetsentryscan.ports import scan_ports

def test_scan_ports_runs():
    res = scan_ports("127.0.0.1", [1, 22], timeout_ms=200)
    assert isinstance(res, list)
    assert all("port" in r and "state" in r for r in res)

