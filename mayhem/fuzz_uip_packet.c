/*
 * libFuzzer harness for iscsiuio's receive path: Ethernet frames go through the
 * real nic.c process_packets() into the uIP stack (ARP, IPv4/TCP/UDP/ICMP, IPv6
 * NDP/ICMPv6/UDP, DHCPv4 client, DHCPv6 client). Only the NIC driver is mocked.
 *
 * Input: byte 0 selects the address configuration; the rest is a sequence of
 * [u16 little-endian length][Ethernet frame] records delivered one by one.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "logger.h"
#include "nic.h"
#include "nic_utils.h"
#include "packet.h"
#include "uip.h"
#include "uip_arp.h"
#include "ipv6_ndpc.h"
#include "dhcpc.h"
#include "timer.h"

#define FUZZ_MAX_FRAMES 16

extern struct dhcpc_options dhcpc_opt;
int do_timers_per_nic_iface(nic_t *nic, nic_interface_t *nic_iface,
			    struct timer *arp_timer);

static const uint8_t *g_data;
static size_t g_size;

static int mock_open(nic_t *nic) { return 0; }
static int mock_close(nic_t *nic, NIC_SHUTDOWN_T how) { return 0; }

static int mock_read(nic_t *nic, packet_t *pkt)
{
	size_t len;

	pkt->buf_size = 0;
	if (g_size < 2)
		return 0;
	len = g_data[0] | (g_data[1] << 8);
	g_data += 2;
	g_size -= 2;
	if (len > g_size)
		len = g_size;
	if (len > pkt->max_buf_size)
		len = pkt->max_buf_size;
	memcpy(pkt->buf, g_data, len);
	g_data += len;
	g_size -= len;
	pkt->buf_size = len;
	return 1;
}

static int mock_write(nic_t *nic, nic_interface_t *iface, packet_t *pkt)
{
	return 0;
}

static void *mock_get_tx_pkt(nic_t *nic) { return NULL; }
static void mock_start_xmit(nic_t *nic, size_t len, u16_t vlan) {}
static int mock_clear_tx_intr(nic_t *nic) { return 0; }

static struct nic_ops mock_ops = {
	.description = "fuzz",
	.open = mock_open,
	.close = mock_close,
	.read = mock_read,
	.write = mock_write,
	.get_tx_pkt = mock_get_tx_pkt,
	.start_xmit = mock_start_xmit,
	.clear_tx_intr = mock_clear_tx_intr,
};

static const uint8_t NIC_MAC[ETH_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	main_log.level = LOG_LEVEL_UNKNOWN;
	dhcpc_opt.enable_random_xid = 0;
	return 0;
}

static nic_interface_t *add_iface(nic_t *nic, uint16_t proto, uint8_t cfg)
{
	nic_interface_t *iface = nic_iface_init();
	struct uip_stack *us;

	if (iface == NULL)
		return NULL;
	iface->protocol = proto;
	iface->vlan_id = 0;
	memcpy(iface->mac_addr, NIC_MAC, ETH_ALEN);
	nic_add_nic_iface(nic, iface);

	us = &iface->ustack;
	uip_init(us, nic->flags & NIC_IPv6_ENABLED);
	memcpy(&us->uip_ethaddr.addr, nic->mac_addr, ETH_ALEN);
	us->ip_config = cfg;
	us->prefix_len = 64;
	us->linklocal_autocfg = IPV6_LL_AUTOCFG_ON;
	us->router_autocfg = IPV6_RTR_AUTOCFG_ON;

	switch (cfg) {
	case IPV4_CONFIG_STATIC: {
		uip_ip4addr_t ip, mask, gw;
		uip_ipaddr(ip, 192, 168, 1, 10);
		uip_ipaddr(mask, 255, 255, 255, 0);
		uip_ipaddr(gw, 192, 168, 1, 1);
		set_uip_stack(us, &ip, &mask, &gw, iface->mac_addr);
		break;
	}
	case IPV4_CONFIG_DHCP:
		set_uip_stack(us, NULL, NULL, NULL, iface->mac_addr);
		dhcpc_init(nic, us, iface->mac_addr, ETH_ALEN);
		break;
	case IPV6_CONFIG_STATIC:
		inet_pton(AF_INET6, "2001:db8::10", us->hostaddr6);
		inet_pton(AF_INET6, "ffff:ffff:ffff:ffff::", us->netmask6);
		inet_pton(AF_INET6, "fe80::1", us->default_route_addr6);
		ndpc_init(nic, us, iface->mac_addr, ETH_ALEN);
		break;
	case IPV6_CONFIG_DHCP:
		ndpc_init(nic, us, iface->mac_addr, ETH_ALEN);
		break;
	}
	return iface;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint8_t v4cfg[4] = { 0, IPV4_CONFIG_STATIC, IPV4_CONFIG_DHCP,
					  IPV4_CONFIG_STATIC };
	static const uint8_t v6cfg[4] = { 0, IPV6_CONFIG_STATIC, IPV6_CONFIG_DHCP,
					  IPV6_CONFIG_DHCP };
	nic_interface_t *v4 = NULL, *v6 = NULL, *it;
	struct timer arp_timer;
	packet_t *p, *pn;
	nic_t *nic;
	uint8_t sel;
	int i;

	if (size < 1)
		return -1;
	sel = data[0];
	g_data = data + 1;
	g_size = size - 1;

	nic = nic_init();
	if (nic == NULL)
		return -1;
	nic->ops = &mock_ops;
	nic->log_name = "fuzz0";
	memcpy(nic->mac_addr, NIC_MAC, ETH_ALEN);
	nic->flags = NIC_ENABLED | NIC_IPv6_ENABLED;
	alloc_free_queue(nic, 1);
	uip_arp_init();
	timer_set(&arp_timer, 1000000);

	if (v4cfg[sel & 3])
		v4 = add_iface(nic, AF_INET, v4cfg[sel & 3]);
	if (v6cfg[(sel >> 2) & 3])
		v6 = add_iface(nic, AF_INET6, v6cfg[(sel >> 2) & 3]);

	/* start the DHCPv4 / NDP state machines, as the periodic timer does */
	if (v4)
		do_timers_per_nic_iface(nic, v4, &arp_timer);
	if (v6)
		do_timers_per_nic_iface(nic, v6, &arp_timer);

	for (i = 0; i < FUZZ_MAX_FRAMES && g_size >= 2; i++)
		process_packets(nic, NULL, NULL, NULL);

	for (it = nic->nic_iface; it != NULL;) {
		nic_interface_t *next = it->next;
		nic_interface_t *vl = it->vlan_next;
		while (vl) {
			nic_interface_t *vn = vl->vlan_next;
			uip_reset(&vl->ustack);
			free(vl);
			vl = vn;
		}
		uip_reset(&it->ustack);
		free(it);
		it = next;
	}
	free_free_queue(nic);
	for (p = nic->tx_packet_queue; p != NULL; p = pn) {
		pn = p->next;
		free(p);
	}
	free(nic);
	return 0;
}
