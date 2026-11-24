import importlib.metadata
import re

import betterleaks


def test_version():
    assert re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?", betterleaks.__version__
    )
    assert importlib.metadata.version("betterleaks") == betterleaks.__version__
