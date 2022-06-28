/*
 * Copyright (c) 2022 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <tll/channel/base.h>
#include <tll/channel/module.h>

#include <tll/util/memoryview.h>
#include <tll/util/size.h>
#include <tll/util/sockaddr.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <pcap.h>

class Child;

long long ts2ts(const struct timeval * tv) { return tv->tv_sec * 1000000000ll + tv->tv_usec; } // ns, not us

class PCap : public tll::channel::Base<PCap>
{
	std::string _filename;
	pcap_t * _pcap = nullptr;
	bool _autoclose = true;
	bool _live = false;
	size_t _snaplen = 1500;
	int _linktype = DLT_EN10MB;

	std::list<Child *> _children;

 public:
	static constexpr std::string_view channel_protocol() { return "pcap"; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);
	int _close();

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

 private:

	template <typename View>
	int _on_ether(tll_msg_t &msg, View view);

	template <typename View>
	int _on_ip(tll_msg_t &msg, View view);

	template <typename View>
	int _on_ipv6(tll_msg_t &msg, View view);

	template <typename Addr>
	int _match(tll_msg_t &msg, const Addr &addr);
};

class Child : public tll::channel::Base<Child>
{
	PCap * _master = nullptr;
	tll::network::sockaddr_any _addr;

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
	if (!reader)
		return _log.fail(EINVAL, "Invalid arguments: {}", reader.error());
	return 0;
}

int PCap::_open(const tll::ConstConfig &)
{
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
		_dcaps_pending(true);
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
	return 0;
}

int PCap::_close()
{
	if (_pcap)
		pcap_close(_pcap);
	_pcap = nullptr;
	_update_fd(-1);
	return 0;
}

template <typename Addr>
int PCap::_match(tll_msg_t &msg, const Addr &addr)
{
	for (auto & c : _children) {
		//_log.debug("Match {} with {}", addr, c->addr());
		if (c && c->addr() == &addr)
			c->_callback_data(&msg);
	}
	return 0;
}

template <typename View>
int PCap::_on_ether(tll_msg_t &msg, View view)
{
	auto ehdr = view.template dataT<ether_header>();
	if (view.size() < sizeof(*ehdr))
		return _log.fail(EINVAL, "Truncated packet: {} < {} ethernet frame size", view.size(), sizeof(*ehdr));
	auto type = ntohs(ehdr->ether_type);
	//_log.debug("Packet type 0x{:x} from {} to {}", type, *(ether_addr *) &ehdr->ether_shost, *(ether_addr *) &ehdr->ether_dhost);
	view = view.view(sizeof(*ehdr));
	switch (type) {
	case ETHERTYPE_IP:
		return _on_ip(msg, view);
	case ETHERTYPE_IPV6:
		return _on_ipv6(msg, view);
	default:
		break;
	}

	_log.debug("Skip non-ip packet 0x{:x}", type);
	return 0;
}

template <typename View>
int PCap::_on_ip(tll_msg_t &msg, View view)
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
		return _match(msg, addr);
	}

	return 0;
}

template <typename View>
int PCap::_on_ipv6(tll_msg_t &msg, View view)
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
		return _match(msg, addr);
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

int PCap::_process(long timeout, int flags)
{
	pcap_pkthdr *hdr;
	const u_char * data;
	auto r = pcap_next_ex(_pcap, &hdr, &data);
	if (r == PCAP_ERROR_BREAK) {
		_log.info("Dump finished");
		if (!_autoclose) {
			_update_fd(-1);
			_update_dcaps(0, tll::dcaps::Process | tll::dcaps::Pending | tll::dcaps::CPOLLIN);
		} else {
			close();
		}
		return 0;
	} else if (r == 0)
		return EAGAIN;
	const tll::const_memory mem = { data, hdr->len };
	auto view = tll::make_view(mem);

	tll_msg_t msg = { TLL_MESSAGE_DATA };
	msg.time = ts2ts(&hdr->ts);

	_log.trace("Capture size {}", view.size());
	switch (_linktype) {
	case DLT_EN10MB:
		_on_ether(msg, view);
		break;
	case DLT_RAW:
		_on_ip(msg, view);
		break;
	}

	msg.data = view.data();
	msg.size = view.size();
	_callback_data(&msg);
	return 0;
}

TLL_DEFINE_IMPL(PCap);
TLL_DEFINE_IMPL(Child);
TLL_DEFINE_MODULE(PCap, Child);
