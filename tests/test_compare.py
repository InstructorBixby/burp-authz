from authzlib import compare

PAGE = (
    "<html><body><h1>Orders</h1>"
    "<input name=\"csrf_token\" value=\"%s\">"
    "<p>generated %s</p>"
    "</body></html>"
)


def resp(status, body="", location=None):
    headers = ["HTTP/1.1 %d" % status, "Content-Type: text/html"]
    if location:
        headers.append("Location: " + location)
    return (status, headers, body)


def test_identical_bodies_are_same():
    assert compare.classify(resp(200, "<p>hi</p>"),
                            resp(200, "<p>hi</p>")) == compare.SAME


def test_unrelated_bodies_are_different():
    assert compare.classify(resp(200, "<p>hi</p>"),
                            resp(200, "nope")) == compare.DIFFERENT


def test_a_403_is_different_from_a_200():
    assert compare.classify(resp(200, "<p>hi</p>"),
                            resp(403, "Forbidden")) == compare.DIFFERENT


def test_no_response_is_error():
    assert compare.classify(resp(200, "<p>hi</p>"),
                            None) == compare.ERROR


def test_csrf_token_is_not_a_difference():
    a = resp(200, PAGE % ("aaaaaaaaaaaa", "2020-11-19T10:00:00Z"))
    b = resp(200, PAGE % ("bbbbbbbbbbbb", "2020-11-19T10:00:04Z"))
    assert compare.classify(a, b) == compare.SAME


def test_redirect_to_the_same_place_is_same():
    a = resp(302, "", "/dashboard")
    b = resp(302, "", "/dashboard")
    assert compare.classify(a, b) == compare.SAME


def test_redirect_to_login_is_not_the_same_as_redirect_to_dashboard():
    a = resp(302, "", "/dashboard")
    b = resp(302, "", "/login?next=/dashboard")
    assert compare.classify(a, b) == compare.DIFFERENT


def test_header_lookup_is_case_insensitive():
    assert compare.header(["location: /x"], "Location") == "/x"


def test_header_lookup_returns_none_when_absent():
    assert compare.header(["Content-Type: text/html"],
                          "Location") is None


def test_a_longer_page_with_one_changed_row_is_similar():
    rows = ["<tr><td>order %d</td></tr>" % i for i in range(200)]
    a = resp(200, "".join(rows))
    b = resp(200, "".join(rows[:-1] + ["<tr><td>gone</td></tr>"]))
    assert compare.classify(a, b) == compare.SIMILAR
