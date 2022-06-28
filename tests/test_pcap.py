#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import pytest

from tll.test_util import Accum

@pytest.fixture
def master(context):
    c = context.Channel('pcap://tests/udp.pcap', name='master', dump='frame', autoclose='yes')
    yield c
    c.close()
    del c

def test_autoclose(master):
    master.open()
    assert master.state == master.State.Active
    for _ in range(20):
        if master.state != master.State.Active:
            break
        master.process()
    assert master.state == master.State.Closed

def test_ipv6(context, master):
    udp = Accum('pcap+udp://fe80::92f6:52ff:fe95:c932:5555', dump='frame', master=master, context=context)
    master.open()
    udp.open()

    for _ in range(100):
        if master.state != master.State.Active:
            break
        master.process()

    assert [m.data.tobytes() for m in udp.result] == [b'ipv6'] * 6

def test_ipv4(context, master):
    u0 = Accum('pcap+udp://10.22.17.253:5555', dump='frame', master=master, context=context)
    u1 = Accum('pcap+udp://10.22.17.253:5556', dump='frame', master=master, context=context)
    master.open()
    u0.open()
    u1.open()

    for _ in range(100):
        if master.state != master.State.Active:
            break
        master.process()

    assert [m.data.tobytes() for m in u0.result] == [b'ipv4:5555'] * 6
    assert [m.data.tobytes() for m in u1.result] == [b'ipv4:5556'] * 6
