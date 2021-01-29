from authzlib import compare

PAGE = (
    "<html><body><h1>Orders</h1>"
    "<input name=\"csrf_token\" value=\"%s\">"
    "<p>generated %s</p>"
    "</body></html>"
)


def test_identical_bodies_are_same():
    assert compare.classify("<p>hello</p>",
                            "<p>hello</p>") == compare.SAME


def test_unrelated_bodies_are_different():
    assert compare.classify("<p>hello</p>",
                            "403 Forbidden") == compare.DIFFERENT


def test_no_response_is_error():
    assert compare.classify("<p>hello</p>", None) == compare.ERROR


def test_csrf_token_is_not_a_difference():
    a = PAGE % ("aaaaaaaaaaaa", "2020-11-19T10:00:00Z")
    b = PAGE % ("bbbbbbbbbbbb", "2020-11-19T10:00:04Z")
    assert compare.classify(a, b) == compare.SAME


def test_scrub_removes_a_timestamp():
    assert "2020-11-19" not in compare.scrub("built 2020-11-19T10:00:00Z")


def test_scrub_removes_a_uuid():
    out = compare.scrub("request 5a9f8d2e-1c4b-4e7a-9f31-0b2c6d8e4a11")
    assert "5a9f8d2e" not in out


def test_scrub_leaves_a_plain_page_alone():
    assert compare.scrub("<p>hello</p>") == "<p>hello</p>"


def test_a_longer_page_with_one_changed_row_is_similar():
    rows = ["<tr><td>order %d</td></tr>" % i for i in range(200)]
    a = "".join(rows)
    b = "".join(rows[:-1] + ["<tr><td>order gone</td></tr>"])
    assert compare.classify(a, b) == compare.SIMILAR
