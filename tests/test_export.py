from authzlib import export


def test_header_row_comes_first():
    out = export.to_csv([])
    assert out.splitlines()[0].startswith("#,method,url,result")


def test_a_row_is_written():
    out = export.to_csv([[1, "GET", "https://t/api/o/1", "same",
                          200, 200]])
    assert "GET,https://t/api/o/1,same,200,200" in out


def test_a_comma_in_a_url_is_quoted():
    out = export.to_csv([[1, "GET", "https://t/a?ids=1,2", "same",
                          200, 200]])
    assert '"https://t/a?ids=1,2"' in out


def test_a_quote_is_doubled():
    out = export.to_csv([[1, "GET", 'https://t/a?q="x"', "same",
                          200, 200]])
    assert '""x""' in out
