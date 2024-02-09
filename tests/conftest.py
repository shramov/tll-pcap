#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import pytest

import os
import pathlib
import tempfile

from tll.channel import Context
import tll.logger
tll.logger.init()

@pytest.fixture
def context():
    ctx = Context()
    ctx.load(os.path.join(os.environ.get("BUILD_DIR", "build"), "tll-pcap"))
    return ctx
