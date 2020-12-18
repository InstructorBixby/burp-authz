from authzlib import compare


def test_same_length_is_same():
    assert compare.classify(1200, 1200) == compare.SAME


def test_different_length_is_different():
    assert compare.classify(1200, 97) == compare.DIFFERENT


def test_no_response_is_error():
    assert compare.classify(1200, None) == compare.ERROR
