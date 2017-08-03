# -*- coding: utf-8 -*-
import random
import string


def make_address():
    return bytes(''.join(random.choice(string.printable) for _ in range(20)))
