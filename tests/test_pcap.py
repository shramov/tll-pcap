#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import decorator
import pytest

from tll.test_util import Accum
from tll import asynctll

@pytest.fixture
def master(context):
    c = context.Channel('pcap://tests/udp.pcap', name='master', dump='frame', autoclose='yes')
    yield c
    c.close()
    del c

@pytest.fixture
def asyncloop(context):
    loop = asynctll.Loop(context)
    yield loop
    loop.destroy()
    loop = None

@decorator.decorator
def asyncloop_run(f, asyncloop, *a, **kw):
    asyncloop.run(f(asyncloop, *a, **kw))

def test_autoclose(master):
    master.open()
    assert master.state == master.State.Active
    for _ in range(100):
        if master.state != master.State.Active:
            break
        master.process()
    assert master.state == master.State.Closed

def test_ipv6(context, master):
    udp = Accum('pcap+udp://fe80::92f6:52ff:fe95:c932:5555', dump='frame', name='udp6', master=master, context=context, autoseq='no')
    master.open()
    udp.open()

    for _ in range(100):
        if master.state != master.State.Active:
            break
        master.process()

    assert [m.data.tobytes() for m in udp.result] == [b'ipv6'] * 6
    assert [m.seq for m in udp.result] == list(range(0, 25 + 1, 5))

def test_ipv4(context, master):
    u0 = Accum('pcap+udp://10.22.17.253:5555', dump='frame', master=master, context=context, name='udp0', autoseq='no')
    u1 = Accum('pcap+udp://10.22.17.253:5556', dump='frame', master=master, context=context, name='udp1', autoseq='no')
    v0 = Accum('pcap+udp://10.23.17.253:5555', dump='frame', master=master, context=context, name='vlan0', vlan='166')
    v1 = Accum('pcap+udp://10.23.17.253:5556', dump='frame', master=master, context=context, name='vlan1', vlan='166')
    master.open()
    u0.open()
    u1.open()
    v0.open()
    v1.open()

    for _ in range(100):
        if master.state != master.State.Active:
            break
        master.process()

    assert [m.data.tobytes() for m in u0.result] == [b'ipv4:5555'] * 6
    assert [m.data.tobytes() for m in u1.result] == [b'ipv4:5556'] * 6
    assert [m.data.tobytes() for m in v0.result] == [b'vlan4:5555'] * 6
    assert [m.data.tobytes() for m in v1.result] == [b'vlan4:5556'] * 6

    assert [m.seq for m in u0.result] == list(range(1, 25 + 2, 5))
    assert [m.seq for m in u1.result] == list(range(2, 25 + 3, 5))
    assert [m.seq for m in v0.result] == list(range(6))
    assert [m.seq for m in v1.result] == list(range(6))

@asyncloop_run
async def test_speed(asyncloop):
    pcap = asyncloop.Channel('pcap://./tests/udp.pcap', name='pcap', speed='100')
    u0 = asyncloop.Channel('pcap+udp://10.22.17.253:5555', dump='frame', master=pcap, name='udp0')
    u1 = asyncloop.Channel('pcap+udp://10.22.17.253:5556', dump='frame', master=pcap, name='udp1')

    pcap.open()
    u0.open()
    u1.open()

    r0, r1 = [], []

    assert await pcap.recv_state() == pcap.State.Active

    for _ in range(6):
        r0 += [await u0.recv(0.011)]
        r1 += [await u1.recv(0.001)]
        with pytest.raises(TimeoutError):
            await u0.recv(0.005)

    assert [m.data.tobytes() for m in r0] == [b'ipv4:5555'] * 6
    assert [m.data.tobytes() for m in r1] == [b'ipv4:5556'] * 6
