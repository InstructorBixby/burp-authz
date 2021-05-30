from authzlib import filters


def test_a_script_is_static():
    assert filters.is_static("/static/app.js")


def test_a_fingerprinted_script_is_static():
    assert filters.is_static("/static/app.1f4c9b.js")


def test_a_query_string_does_not_hide_the_extension():
    assert filters.is_static("/static/app.js?v=3")


def test_an_api_path_is_not_static():
    assert not filters.is_static("/api/orders")


def test_case_does_not_matter():
    assert filters.is_static("/IMG/Logo.PNG")


def test_an_empty_path_is_not_static():
    assert not filters.is_static("")


def test_an_api_call_is_interesting():
    assert filters.interesting("GET", "/api/orders/4")
