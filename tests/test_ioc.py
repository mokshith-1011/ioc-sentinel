from ioc import detect_ioc_type

def test_ip():
    assert detect_ioc_type("8.8.8.8") == "ip"

def test_domain():
    assert detect_ioc_type("example.com") == "domain"

def test_url():
    assert detect_ioc_type("https://example.com/login") == "url"

def test_sha256():
    assert detect_ioc_type("a" * 64) == "sha256"

def test_unknown():
    assert detect_ioc_type("not-an-ioc") == "unknown"
