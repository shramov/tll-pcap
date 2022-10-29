/*
 * Copyright (c) 2022 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <tll/channel/base.h>
#include <tll/channel/module.h>

#include <tll/scheme/channel/timer.h>

#include <tll/util/memoryview.h>
#include <tll/util/size.h>
#include <tll/util/sockaddr.h>
#include <tll/util/time.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <pcap.h>
#include <pcap/vlan.h>

class Child;

tll::time_point ts2ts(const struct timeval * tv)
{
	return tll::time_point { std::chrono::seconds(tv->tv_sec) + std::chrono::nanoseconds(tv->tv_usec) };
}

class PCap : public tll::channel::Base<PCap>
{
	std::string _filename;
	pcap_t * _pcap = nullptr;
	bool _autoclose = true;
	bool _live = false;
	size_t _snaplen = 1500;
	int _linktype = DLT_EN10MB;

	std::list<Child *> _children;

	pcap_pkthdr * _pcap_hdr = nullptr;
	const u_char * _pcap_data = nullptr;

	long long _seq = 0;
	double _speed = 0;
	tll::time_point _pcap_epoch = {};
	tll::time_point _wall_epoch = {};
	std::unique_ptr<tll::Channel> _timer;

	std::string _filter;

 public:
	static constexpr std::string_view channel_protocol() { return "pcap"; }
	static constexpr auto process_policy() { return ProcessPolicy::Custom; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);
	int _close();
	void _free()
	{
		_timer.reset();
	}

	int _process(long timeout, int flags);

	void reg(Child * ptr)
	{
		for (auto & p : _children) {
			if (!p) {
				p = ptr;
				return;
			}
		}
		_children.push_back(ptr);
	}

	void unreg(Child * ptr)
	{
		for (auto & p : _children) {
			if (p == ptr)
				p = nullptr;
		}
	}

	int callback(const tll::Channel * c, const tll_msg_t * msg);

 private:
	struct Frame
	{
		unsigned short vlan = 0;
	};

	int _on_pcap(pcap_pkthdr * hdr, const u_char * data);
	tll::time_point _when(const tll::time_point &now, const tll::time_point &ts);

	int _pcap_read();

	template <typename View>
	int _on_ether(tll_msg_t &msg, Frame &frame, View view);

	template <typename View>
	int _on_ip(tll_msg_t &msg, Frame &frame, View view);

	template <typename View>
	int _on_ipv6(tll_msg_t &msg, Frame &frame, View view);

	template <typename Addr>
	int _match(tll_msg_t &msg, const Frame &frame, const Addr &addr);

	int _rearm(const tll::time_point &ts)
	{
		timer_scheme::absolute m = { ts };
		tll_msg_t msg = {};
		msg.type = TLL_MESSAGE_DATA;
		msg.msgid = m.id;
		msg.data = &m;
		msg.size = sizeof(m);
		if (_timer->post(&msg))
			return _log.fail(EINVAL, "Failed to rearm timer");
		return 0;
	}
};

class Child : public tll::channel::Base<Child>
{
	PCap * _master = nullptr;
	tll::network::sockaddr_any _addr;
	unsigned short _vlan = 0;
	long long _seq = 0;
	bool _autoseq = true;

 public:
	static constexpr std::string_view channel_protocol() { return "pcap+udp"; }
	static constexpr auto process_policy() { return ProcessPolicy::Never; }

	int _init(const tll::Channel::Url &url, tll::Channel *master)
	{
		_master = tll::channel_cast<PCap>(master);
		if (!_master)
			return _log.fail(EINVAL, "Need pcap master channel");

		auto reader = channel_props_reader(url);
		auto af = reader.getT("af", tll::network::AddressFamily::UNSPEC);
		_vlan = reader.getT<unsigned short>("vlan", 0);
		_autoseq = reader.getT("autoseq", true);
		if (!reader)
			return _log.fail(EINVAL, "Invalid arguments: {}", reader.error());
		auto r = tll::network::parse_hostport(url.host(), af);
		if (!r)
			return _log.fail(EINVAL, "Invalid host:port pair '{}': {}", url.host(), r.error());
		if (r->af == AF_UNIX)
			return _log.fail(EINVAL, "Unix socket address not supported");
		auto l = tll::network::resolve(r->af, SOCK_DGRAM, r->host, r->port);
		if (!l)
			return this->_log.fail(EINVAL, "Failed to resolve '{}': {}", r->host, l.error());
		_addr = l->front();
		_log.info("Capture packets for {}", _addr);
		return 0;
	}

	int _open(const tll::ConstConfig &)
	{
		_master->reg(this);
		_seq = 0;
		return 0;
	}

	int _close()
	{
		_master->unreg(this);
		return 0;
	}

	//const tll::network::sockaddr_any & addr() const { return _addr; }
	//tll::network::sockaddr_any & addr() { return _addr; }
	auto & addr() { return _addr; }
	auto vlan() const { return _vlan; }
	auto autoseq() { return _autoseq; }
	auto & seq() { return _seq; }
};

int PCap::_init(const tll::Channel::Url &url, tll::Channel *master)
{
	_filename = url.host();
	if (!_filename.size())
		return _log.fail(EINVAL, "Empty pcap filename");
	auto reader = channel_props_reader(url);
	_autoclose = reader.getT("autoclose", true);
	_live = reader.getT("live", false);
	_snaplen = reader.getT("snaplen", tll::util::Size { 1500 });
	_speed = reader.getT<double>("speed", 0);
	_filter = reader.getT<std::string>("filter", "");
	if (!reader)
		return _log.fail(EINVAL, "Invalid arguments: {}", reader.error());

	if (_speed < 0)
		return _log.fail(EINVAL, "Negative speed divisor: {}", _speed);
	if (_speed) {
		if (_live)
			return _log.fail(EINVAL, "Can not set speed of live capture");
		auto curl = child_url_parse("timer://;clock=realtime", "timer");
		if (!curl)
			return _log.fail(EINVAL, "Failed to parse timer url: {}", curl.error());
		_timer = context().channel(*curl);
		if (!_timer)
			return _log.fail(EINVAL, "Failed to create timer");
		_timer->callback_add(this);
		internal.caps |= tll::caps::Parent;
		_child_add(_timer.get(), "timer");
	}
	return 0;
}

int PCap::_open(const tll::ConstConfig &)
{
	_pcap_hdr = nullptr;
	_pcap_data = nullptr;
	_seq = 0;

	char errbuf[PCAP_ERRBUF_SIZE];
	if (_live) {
		_log.debug("Open live device {}", _filename);
		_pcap = pcap_create(_filename.c_str(), errbuf); 
		if (!_pcap)
			return _log.fail(EINVAL, "Failed to open device '{}': {}", _filename, errbuf);
		if (pcap_set_timeout(_pcap, 1))
			return _log.fail(EINVAL, "Failed to set timeout");
		if (pcap_set_snaplen(_pcap, _snaplen))
			return _log.fail(EINVAL, "Failed to set snaplen to {}", _snaplen);
		if (pcap_set_promisc(_pcap, 1))
			return _log.fail(EINVAL, "Failed to set promisc mode");
		if (pcap_set_tstamp_precision(_pcap, PCAP_TSTAMP_PRECISION_NANO))
			return _log.fail(EINVAL, "Failed to set tstamp precision");
		if (pcap_setnonblock(_pcap, 1, errbuf))
			return _log.fail(EINVAL, "Failed to set nonblock: {}", errbuf);
		if (pcap_activate(_pcap))
			return _log.fail(EINVAL, "Failed to activate pcap: {}", pcap_geterr(_pcap));
		auto fd = pcap_get_selectable_fd(_pcap);
		if (fd != PCAP_ERROR) {
			_update_fd(fd);
			_update_dcaps(tll::dcaps::CPOLLIN);
		} else
			_dcaps_pending(true);
	} else {
		_log.debug("Open pcap file {}", _filename);
		_pcap = pcap_open_offline_with_tstamp_precision(_filename.c_str(), PCAP_TSTAMP_PRECISION_NANO, errbuf);
		if (!_pcap)
			return _log.fail(EINVAL, "Failed to open file '{}': {}", _filename, errbuf);
	}

	if (_filter.size()) {
		struct bpf_program bpf = {};
		if (pcap_compile(_pcap, &bpf, _filter.c_str(), 1, PCAP_NETMASK_UNKNOWN))
			return _log.fail(EINVAL, "Failed to compile BPF: {}\n\t{}", pcap_geterr(_pcap), _filter);
		auto r = pcap_setfilter(_pcap, &bpf);
		pcap_freecode(&bpf);
		if (r)
			return _log.fail(EINVAL, "Failed to set BPF filter: {}", pcap_geterr(_pcap));
	}

	_linktype = pcap_datalink(_pcap);
	if (_linktype == PCAP_ERROR_NOT_ACTIVATED)
		return _log.fail(EINVAL, "Failed to get link type: pcap handle not active");
	switch (_linktype) {
	case DLT_EN10MB: _log.debug("Link type: ethernet"); break;
	case DLT_RAW: _log.debug("Link type: raw ip"); break;
	default:
		return _log.fail(EINVAL, "Unknown link type: {}", _linktype);
	}

	if (_speed) {
		_update_dcaps(0, tll::dcaps::Process | tll::dcaps::Pending);
		if (_timer->open())
			return _log.fail(EINVAL, "Failed to open timer channel");
		_rearm(tll::time::now());
	} else
		_update_dcaps(tll::dcaps::Pending | tll::dcaps::Process);

	return 0;
}

int PCap::_close()
{
	if (_pcap)
		pcap_close(_pcap);
	_pcap = nullptr;
	_update_fd(-1);
	for (auto & c : _children) {
		if (c)
			c->close();
	}
	return 0;
}

template <typename Addr>
int PCap::_match(tll_msg_t &msg, const PCap::Frame &frame, const Addr &addr)
{
	for (auto & c : _children) {
		//_log.debug("Match {} with {}", addr, c->addr());
		if (!c)
			continue;
		if (c->vlan() != frame.vlan)
			continue;
		if (c->addr() != &addr)
			continue;
		auto seq = msg.seq;
		if (c->autoseq())
			msg.seq = c->seq()++;
		c->_callback_data(&msg);
		msg.seq = seq;
		return 0;
	}
	return 0;
}

template <typename View>
int PCap::_on_ether(tll_msg_t &msg, Frame &frame, View view)
{
	auto ehdr = view.template dataT<ether_header>();
	if (view.size() < sizeof(*ehdr))
		return _log.fail(EINVAL, "Truncated packet: {} < {} ethernet frame size", view.size(), sizeof(*ehdr));
	auto type = ntohs(ehdr->ether_type);
	//_log.debug("Packet type 0x{:x} from {} to {}", type, *(ether_addr *) &ehdr->ether_shost, *(ether_addr *) &ehdr->ether_dhost);
	view = view.view(sizeof(*ehdr));
	while (true) {
		_log.trace("Check ethertype 0x{:04x}", type);
		switch (type) {
		case ETHERTYPE_IP:
			return _on_ip(msg, frame, view);
		case ETHERTYPE_IPV6:
			return _on_ipv6(msg, frame, view);
		case ETHERTYPE_VLAN: {
			if (view.size() < sizeof(vlan_tag))
				return _log.fail(EINVAL, "Truncated packet: {} < {} vlan frame size", view.size(), sizeof(vlan_tag));
			auto vhdr = view.template dataT<uint16_t>();
			frame.vlan = ntohs(*vhdr & 0xfff0u);
			type = ntohs(vhdr[1]);
			_log.debug("Handle VLAN header: {}", frame.vlan);
			view = view.view(sizeof(vlan_tag));
			break;
		}
		default:
			_log.debug("Skip non-ip packet 0x{:x}", type);
			return 0;
		}
	}
	return 0;
}

template <typename View>
int PCap::_on_ip(tll_msg_t &msg, Frame &frame, View view)
{
	_log.trace("IP packet size {}", view.size());

	if (view.size() < sizeof(struct iphdr))
		return _log.fail(EINVAL, "Truncated packet: {} < {} ip header size", view.size(), sizeof(iphdr));
	auto ip = view.template dataT<iphdr>();
	auto proto = ip->protocol;
	_log.trace("IP {} > {} {}", *(in_addr *) &ip->saddr, *(in_addr *) &ip->daddr, proto);
	view = view.view(sizeof(iphdr));

	if (proto == IPPROTO_UDP) {
		auto udp = view.template dataT<udphdr>();

		sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = ip->daddr;;
		addr.sin_port = udp->uh_dport;

		view = view.view(sizeof(*udp));
		msg.data = view.data();
		msg.size = view.size();
		return _match(msg, frame, addr);
	}

	return 0;
}

template <typename View>
int PCap::_on_ipv6(tll_msg_t &msg, Frame &frame, View view)
{
	_log.trace("IPv6 packet size {}", view.size());

	if (view.size() < sizeof(struct ip6_hdr))
		return _log.fail(EINVAL, "Truncated packet: {} < {} ip header size", view.size(), sizeof(iphdr));
	auto ip = view.template dataT<ip6_hdr>();
	auto proto = ip->ip6_nxt;
	_log.trace("IPv6 {} > {} {}", ip->ip6_src, ip->ip6_dst, proto);
	view = view.view(sizeof(ip6_hdr));

	if (proto == IPPROTO_UDP) {
		auto udp = view.template dataT<udphdr>();

		sockaddr_in6 addr = {};
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = ip->ip6_dst;;
		addr.sin6_port = udp->uh_dport;

		view = view.view(sizeof(*udp));
		msg.data = view.data();
		msg.size = view.size();
		return _match(msg, frame, addr);
	}

	/*
	do {
		switch (proto) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_ICMPV6:
		case IPPROTO_NONE:
		case IPPROTO_DSTOPTS:
		case IPPROTO_MH:
			break;
		}
	} while (true);
	*/
	return 0;
}

int PCap::_pcap_read()
{
	auto r = pcap_next_ex(_pcap, &_pcap_hdr, &_pcap_data);
	if (r == 1)
		return 0;
	else if (r == 0) // No data available from live capture
		return EAGAIN;

	if (r == PCAP_ERROR_BREAK) {
		_log.info("Dump finished");
		if (!_autoclose) {
			_update_fd(-1);
			_update_dcaps(0, tll::dcaps::Process | tll::dcaps::Pending | tll::dcaps::CPOLLIN);
			if (_timer)
				_timer->close();
		} else {
			close();
		}
		return EAGAIN;
	}

	return state_fail(EINVAL, "Failed to read data from pcap: {}", pcap_geterr(_pcap));
}

int PCap::_process(long timeout, int flags)
{
	if (auto r = _pcap_read(); r)
		return r;
	return _on_pcap(_pcap_hdr, _pcap_data);
}

int PCap::callback(const tll::Channel * c, const tll_msg_t * msg)
{
	if (msg->type != TLL_MESSAGE_DATA)
		return 0;
	if (!_pcap_hdr) {
		if (auto r = _pcap_read(); r)
			return r;
	}

	auto hdr = _pcap_hdr;
	auto ts = ts2ts(&hdr->ts);
	auto now = tll::time::now();
	auto next = _when(now, ts);
	if (next > now) {
		_rearm(next);
		return EAGAIN;
	}

	_pcap_hdr = nullptr;

	if (auto r = _on_pcap(hdr, _pcap_data); r)
		return r;
	
	if (!_pcap) // Closed in callback
		return 0;
	
	if (auto r = _pcap_read(); r)
		return r;

	now = tll::time::now();
	_rearm(_when(now, ts2ts(&_pcap_hdr->ts)));
	return 0;
}

tll::time_point PCap::_when(const tll::time_point &now, const tll::time_point &ts)
{
	if (!_speed)
		return now;

	if (_pcap_epoch == tll::time_point {}) {
		_pcap_epoch = ts;
		_wall_epoch = now;
	}

	return _wall_epoch + std::chrono::duration_cast<tll::duration>((ts - _pcap_epoch) / _speed);
}

int PCap::_on_pcap(pcap_pkthdr * hdr, const u_char * data)
{
	const tll::const_memory mem = { data, hdr->len };
	auto view = tll::make_view(mem);

	tll_msg_t msg = { TLL_MESSAGE_DATA };
	msg.seq = _seq;
	msg.time = ts2ts(&hdr->ts).time_since_epoch().count();

	Frame frame = {};

	_log.trace("Capture size {}", view.size());
	switch (_linktype) {
	case DLT_EN10MB:
		_on_ether(msg, frame, view);
		break;
	case DLT_RAW:
		_on_ip(msg, frame, view);
		break;
	}

	msg.data = view.data();
	msg.size = view.size();
	msg.seq = _seq;
	_seq++;
	_callback_data(&msg);
	return 0;
}

TLL_DEFINE_IMPL(PCap);
TLL_DEFINE_IMPL(Child);
TLL_DEFINE_MODULE(PCap, Child);
