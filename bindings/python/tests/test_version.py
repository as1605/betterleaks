import betterleaks


def test_version():
    assert betterleaks.__version__ == "0.1.0"
    assert betterleaks.__upstream_version__ == "2.0.0-rc.14"
