/* 
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of ukvm, a unikernel monitor.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ukvm_module_netmap.c: Netmap port device module.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <linux/kvm.h>

#include <net/netmap_user.h>

#include "ukvm.h"
#include "ukvm_guest.h"
#include "ukvm_hv_kvm.h"
#include "ukvm_cpu_x86_64.h"

#ifdef __linux__
#define sockaddr_dl    sockaddr_ll
#define sdl_family     sll_family
#define AF_LINK        AF_PACKET
#define LLADDR(s)      s->sll_addr;
#endif

#define NUM_TX_SLOTS NUM_NETMAP_SLOTS
#define NUM_RX_SLOTS NUM_TX_SLOTS
#define NUM_TX_RINGS 1
#define NUM_RX_RINGS NUM_TX_RINGS

#define TX_METADATA_SIZE 0x5000
#define RX_METADATA_SIZE 0x5000

struct nm_data{
	struct nmreq nmreq;
	uint64_t nmd_flags;
	struct nm_desc *nmdesc;
};

/* For Netmap devices */
static struct nm_data *port;
static int nmd_fd;
static struct netmap_ring *txring, *rxring;
static uint32_t tx_buf_size, rx_buf_size;
static char *netiface;
static struct ukvm_netinfo netinfo;
static struct ukvm_netmap_ringinfo rinfo;

static inline int need_next_slot(uint16_t flags)
{
	return (flags & NS_MOREFRAG);
}

static void hypercall_netmap_ringinfo(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
	struct ukvm_netmap_ringinfo *ringinfo =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_netmap_ringinfo));

	memcpy(ringinfo, &rinfo, sizeof(struct ukvm_netmap_ringinfo));

	/* RX buffer information in GPA */
	printf("RX ring address info in the Guest OS:\n");
	printf("ring_base = 0x%"PRIx64", buf_base = 0x%"PRIx64", num_slots = %"PRIu32", nr_buf_size = %"PRIu32", head_addr = 0x%"PRIx64", cur_addr = 0x%"PRIx64", tail_addr = 0x%"PRIx64", slot_base = 0x%"PRIx64", index_offset = %"PRIu32"\n", ringinfo->rx.ring_base, ringinfo->rx.buf_base, ringinfo->rx.num_slots, ringinfo->rx.nr_buf_size, ringinfo->rx.head_addr, ringinfo->rx.cur_addr, ringinfo->rx.tail_addr, ringinfo->rx.slot_base, ringinfo->rx.index_offset);
	/* TX buffer information in GPA */
	printf("TX ring address info in the Guest OS:\n");
	printf("ring_base = 0x%"PRIx64", buf_base = 0x%"PRIx64", num_slots = %"PRIu32", nr_buf_size = %"PRIu32", head_addr = 0x%"PRIx64", cur_addr = 0x%"PRIx64", tail_addr = 0x%"PRIx64", slot_base = 0x%"PRIx64", index_offset = %"PRIu32"\n", ringinfo->tx.ring_base, ringinfo->tx.buf_base, ringinfo->tx.num_slots, ringinfo->tx.nr_buf_size, ringinfo->tx.head_addr, ringinfo->tx.cur_addr, ringinfo->tx.tail_addr, ringinfo->tx.slot_base, ringinfo->tx.index_offset);

	ringinfo->ret = 0;

	return ;
}

/* Not changed from hypercall_netinfo() */
static void hypercall_netmapinfo(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_netinfo *info =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_netinfo));

    memcpy(info->mac_str, netinfo.mac_str, sizeof(netinfo.mac_str));
	return ;
}

/* Just sending packet(s) stored in the TX ring buffer by the guest OS */
static void hypercall_netmapwrite(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    int *i =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof(int));
    int ret = 0;

	if (ioctl(nmd_fd, NIOCTXSYNC, NULL) < 0) {
		err(1, "ioctl error on the TX queue#0: NIOCTXSYNC");
		ret = -1;
	}

	*i = ret;
	return ;
}

/* Do nothing (should not be called) */
static void hypercall_netmapread(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    int *i =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof(int));
    int ret = 0;

	if (ioctl(nmd_fd, NIOCRXSYNC, NULL) < 0) {
		err(1, "ioctl error on the TX queue#0: NIOCTXSYNC");
		ret = -1;
	}

	*i = ret;
	return ;
}

static int handle_cmdarg(char *cmdarg)
{
    if (!strncmp("--netmap=", cmdarg, 9)) {
        netiface = cmdarg + 9;
        return 0;
    } else {
        return -1;
    }
}

/*
 * locate the src mac address for our interface, put it
 * into the user-supplied buffer. return 0 if ok, -1 on error.
 */
static int source_hwaddr(const char *ifname, char *buf)
{
    struct ifaddrs *ifaphead, *ifap;

    if (getifaddrs(&ifaphead) != 0) {
        warnx("getifaddrs %s failed", ifname);
        return -1;
    }

    for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
        struct sockaddr_dl *sdl =
            (struct sockaddr_dl *)ifap->ifa_addr;
        uint8_t *mac;

        if (!sdl || sdl->sdl_family != AF_LINK)
            continue;
        if (strncmp(ifap->ifa_name, ifname, IFNAMSIZ) != 0)
            continue;
        mac = (uint8_t *)LLADDR(sdl);
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
        break;
    }
    freeifaddrs(ifaphead);
    return ifap ? 0 : 1;
}

static int setup(struct ukvm_hv *hv)
{
	int i, ret = 0;
	char *ifname;
	static struct kvm_userspace_memory_region rxring_region, txring_region;

	txring = rxring = NULL;
	tx_buf_size = rx_buf_size = 0;

	if (netiface == NULL)
		return -1;

	printf("----- netmap module initialization -----\n");

	/* Obtain the MAC address */
	if (source_hwaddr(netiface, netinfo.mac_str) == -1) {
		err(1, "Could not get the MAC address: %s", netiface);
		return -1;
	}
	printf("Netmap port: MAC address(%s) on %s\n", netinfo.mac_str, netiface);

	/* Allocate the Netmap data */
	if ((port = calloc(1, sizeof(struct nm_data))) == NULL) {
		err(1, "Memory allocation error: port");
		return -1;
	}
	
	if ((ifname = malloc(sizeof(char) * (8 + strlen(netiface)))) == NULL) {
		err(1, "Memory allocation error: ifname");
		goto err_ifname;
	}
	snprintf(ifname, 8 + strlen(netiface), "netmap:%s", netiface);

	struct nmreq *base = &port->nmreq;
	base->nr_tx_slots = NUM_TX_SLOTS;
	base->nr_rx_slots = NUM_RX_SLOTS;
	base->nr_tx_rings = NUM_TX_RINGS;
	base->nr_rx_rings = NUM_RX_RINGS;

	/* TODO: how to deal with NETMAP_NO_TX_POLL */
	if ((port->nmdesc = nm_open(ifname, base, 0, NULL)) == NULL) {
		err(1, "Failed to open a Netmap port %s\n", ifname);
		goto err_open;
	}
	nmd_fd = port->nmdesc->fd;
	if (nmd_fd < 0) {
		err(1, "Something wrong in a flie descriptor.\n");
		goto err_open;
	};

	/* port information output */
	struct netmap_if *nifp = port->nmdesc->nifp;
	struct nmreq *req = &port->nmdesc->req;
	printf("mapped %dKB at %p\n", req->nr_memsize >> 10, port->nmdesc->mem);
	printf("# of TX queues: %d, # of RX queues: %d\n", req->nr_tx_rings, req->nr_rx_rings);
	printf("# of TX slots: %d, # of RX slots: %d\n", req->nr_tx_slots, req->nr_rx_slots);
	printf("Detail:\n");
	printf("    nifp at offset 0x%X\n", req->nr_offset);
	/* Just for ring checking */
	for(i = 0; i < req->nr_tx_rings; i++){
		struct netmap_ring *ring = NETMAP_TXRING(nifp, i);
		printf("    TX(%d) at %p / # of slots: %d\n", i, (void *)((char *)ring - (char *)nifp), ring->num_slots);
		if (ring->num_slots < NUM_TX_SLOTS) {
			err(1, "Shortage in the number of TX slots. it must be greater or equal to 64");
			goto err_config;
		}
	}
	for(i = 0; i < req->nr_rx_rings; i++){
		struct netmap_ring *ring = NETMAP_RXRING(nifp, i);
		printf("    RX(%d) at %p / # of slots: %d\n", i, (void *)((char *)ring - (char *)nifp), ring->num_slots);
		if (ring->num_slots < NUM_RX_SLOTS) {
			err(1, "Shortage in the number of TX slots. it must be greater or equal to 64");
			goto err_config;
		}
	}
	/* We use only the first ring pair */
	txring = NETMAP_TXRING(nifp, 0);
	rxring = NETMAP_RXRING(nifp, 0);
	tx_buf_size = txring->nr_buf_size;
	rx_buf_size = rxring->nr_buf_size;
	printf("    Slot buffer size: TX(%d)-%dBytes, RX(%d)-%dBytes\n", 0, tx_buf_size, 0, rx_buf_size);

    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETMAPINFO,
                hypercall_netmapinfo) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETMAPWRITE,
                hypercall_netmapwrite) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETMAPREAD,
                hypercall_netmapread) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETMAP_RINGINFO,
                hypercall_netmap_ringinfo) == 0);
    assert(ukvm_core_register_pollfd(nmd_fd) == 0);

	/* TODO: adjust the sleeping period for Netmap device stabilization */
	printf("Waiting for device reset: %s\n", ifname);
	sleep(3);

	free(ifname);

	/* Buffer size checking */
    uint64_t total_netmap_buf_size = TX_METADATA_SIZE + RX_METADATA_SIZE
        + (uint64_t)(rxring->num_slots * rxring->nr_buf_size) + (uint64_t)(txring->num_slots * txring->nr_buf_size);
	uint64_t total_pagesize = 0x0;
	do{
		total_pagesize += X86_GUEST_PAGE_SIZE;
	}while(total_pagesize < total_netmap_buf_size);
	if ((hv->mem_size + total_netmap_buf_size) > (X86_GUEST_PAGE_SIZE * 512)) {
        err(1, "guest memory size exceeds the max size %u bytes", X86_GUEST_PAGE_SIZE * 512);
		goto err_open;
	}

	uint64_t offset = 0x0;
	/* Register the RX/TX ring buffers with KVM */
	/* RX metadata */
	rxring_region.slot = UKVM_NETMAP_RXRING_META_REGION;
	rxring_region.guest_phys_addr = hv->mem_size + offset;
	rxring_region.memory_size = RX_METADATA_SIZE; 
	rxring_region.userspace_addr = (uint64_t)rxring;
	ret = ioctl(hv->b->vmfd, KVM_SET_USER_MEMORY_REGION, &rxring_region);
	if (ret == -1) {
		err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) failed: Netmap RX metadata");
		goto err_open;
	}
	rinfo.rx.ring_base = rxring_region.guest_phys_addr;
	rinfo.rx.num_slots = rxring->num_slots;
	rinfo.rx.nr_buf_size = rxring->nr_buf_size;
	rinfo.rx.head_addr = rxring_region.guest_phys_addr + (uint64_t)(&rxring->head) - (uint64_t)rxring;
	rinfo.rx.cur_addr = rxring_region.guest_phys_addr + (uint64_t)(&rxring->cur) - (uint64_t)rxring;
	rinfo.rx.tail_addr = rxring_region.guest_phys_addr + (uint64_t)(&rxring->tail) - (uint64_t)rxring;
	rinfo.rx.slot_base = rxring_region.guest_phys_addr + (uint64_t)(rxring->slot) - (uint64_t)rxring;
	rinfo.rx.index_offset = rxring->slot[0].buf_idx;
	offset += rxring_region.memory_size;
	/* RX ring buffer */
	rxring_region.slot = UKVM_NETMAP_RXRING_BUF_REGION;
	rxring_region.guest_phys_addr = hv->mem_size + offset;
	rxring_region.memory_size = (uint64_t)(rxring->num_slots * rxring->nr_buf_size);
	rxring_region.userspace_addr = (uint64_t)rxring + rxring->buf_ofs + rxring->slot[0].buf_idx * rxring->nr_buf_size;
	ret = ioctl(hv->b->vmfd, KVM_SET_USER_MEMORY_REGION, &rxring_region);
	if (ret == -1) {
		err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) failed: Netmap RX ring buffer");
		goto err_open;
	}
	rinfo.rx.buf_base = rxring_region.guest_phys_addr;
	offset += rxring_region.memory_size;

	/* TX metadata */
	txring_region.slot = UKVM_NETMAP_TXRING_META_REGION;
	txring_region.guest_phys_addr = hv->mem_size + offset;
	txring_region.memory_size = TX_METADATA_SIZE;
	txring_region.userspace_addr = (uint64_t)txring;
	ret = ioctl(hv->b->vmfd, KVM_SET_USER_MEMORY_REGION, &txring_region);
	if (ret == -1) {
		err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) failed: Netmap TX metadata");
		goto err_open;
	}
	rinfo.tx.ring_base = txring_region.guest_phys_addr;
	rinfo.tx.num_slots = txring->num_slots;
	rinfo.tx.nr_buf_size = txring->nr_buf_size;
	rinfo.tx.head_addr = txring_region.guest_phys_addr + (uint64_t)(&txring->head) - (uint64_t)txring;
	rinfo.tx.cur_addr = txring_region.guest_phys_addr + (uint64_t)(&txring->cur) - (uint64_t)txring;
	rinfo.tx.tail_addr = txring_region.guest_phys_addr + (uint64_t)(&txring->tail) - (uint64_t)txring;
	rinfo.tx.slot_base = txring_region.guest_phys_addr + (uint64_t)(txring->slot) - (uint64_t)txring;
	rinfo.tx.index_offset = txring->slot[0].buf_idx;
	offset += txring_region.memory_size;
	/* TX ring buffer */
	txring_region.slot = UKVM_NETMAP_TXRING_BUF_REGION;
	txring_region.guest_phys_addr = hv->mem_size + offset;
	txring_region.memory_size = (uint64_t)(txring->num_slots * txring->nr_buf_size);
	txring_region.userspace_addr = (uint64_t)txring + txring->buf_ofs + txring->slot[0].buf_idx * txring->nr_buf_size;
	ret = ioctl(hv->b->vmfd, KVM_SET_USER_MEMORY_REGION, &txring_region);
	if (ret == -1) {
		err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) failed: Netmap TX ring buffer");
		goto err_open;
	}
	rinfo.tx.buf_base = txring_region.guest_phys_addr;
	offset += txring_region.memory_size;

	/* Setting pagetables for Netmap buffers */
	printf("offset = 0x%"PRIx64", total_pagesize = 0x%"PRIx64"\n", offset, total_pagesize);
    ukvm_x86_add_pagetables(hv->mem, hv->mem_size, total_pagesize);

	printf("----- netmap module initialization finished -----\n\n");
    return 0;

err_config:
	nm_close(port->nmdesc);
err_open:
	free(ifname);
err_ifname:
	free(port);
	return -1;
}

int nm_finalize(void)
{
	if (port) {
		if (port->nmdesc) {
			if (nm_close(port->nmdesc)) {
				err(1, "nm_close() failed");
				return -1;
			}
		}
		free(port);
	}

	return 0;
}

static char *usage(void)
{
    return "--netmap=DEVNAME (host network device which is \"Netmap-ready\")\n";
}

struct ukvm_module ukvm_module_netmap = {
    .name = "netmap",
    .setup = setup,
    .handle_cmdarg = handle_cmdarg,
    .usage = usage
};
