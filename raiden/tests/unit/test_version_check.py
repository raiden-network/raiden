import re

from raiden.tasks import SECURITY_EXPRESSION


def test_version_check_regex():
    text1 = "Something OTHER UPDATE. [CRITICAL UPDATE Some text.:)]. Something else."
    text2 = "\n\n[CRITICAL\t UPDATE] some text goes here."
    text3 = "[NOTHING]"
    text4 = "asd[CRITICAL UPDATE]"
    text5 = "Other text [CRITICAL UPDATE:>>>>>>>]><<<<asdeqsffqwe qwe sss."
    text6 = "\n\n[CRITICAL UPDATE: U+1F00 1F62D ❎	😀] some text goes here."
    assert re.search(SECURITY_EXPRESSION, text1).group(0) == '[CRITICAL UPDATE Some text.:)]'
    assert re.search(SECURITY_EXPRESSION, text2) is None
    assert re.search(SECURITY_EXPRESSION, text3) is None
    assert re.search(SECURITY_EXPRESSION, text4).group(0) == '[CRITICAL UPDATE]'
    assert re.search(SECURITY_EXPRESSION, text5).group(0) == '[CRITICAL UPDATE:>>>>>>>]'
    assert re.search(SECURITY_EXPRESSION, text6).group(0) == '[CRITICAL UPDATE: U+1F00 1F62D ❎	😀]'
    assert re.search(SECURITY_EXPRESSION, text6).group(0) != '[CRITICAL UPDATE: U+1F00 1F62D ❎'
