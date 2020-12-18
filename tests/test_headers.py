from authzlib import headers as hdr

REQUEST = [
    "GET /admin/users HTTP/1.1",
    "Host: target.example",
    "Cookie: session=admin-session",
    "Accept: application/json",
]


def test_name_of_is_lowercased():
    assert hdr.name_of("Content-Type: application/json") == "content-type"


def test_drop_removes_by_name():
    out = hdr.drop(REQUEST, ["cookie"])
    assert "Cookie: session=admin-session" not in out
    assert "Accept: application/json" in out


def test_replace_keeps_the_request_line_first():
    out = hdr.replace(REQUEST, ["Cookie: session=lowpriv"])
    assert out[0] == "GET /admin/users HTTP/1.1"
    assert out[-1] == "Cookie: session=lowpriv"


def test_replace_drops_the_old_header():
    out = hdr.replace(REQUEST, ["Cookie: session=lowpriv"])
    assert "Cookie: session=admin-session" not in out


def test_replace_handles_an_empty_list():
    assert hdr.replace([], ["Cookie: x"]) == ["Cookie: x"]
