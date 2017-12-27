/* 
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a unikernel base layer.
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

#include "kernel.h"
#include "netmap_if.h"

static struct ukvm_netmap_ringinfo ringinfo;
static struct ukvm_netmap_guestring rx, tx;
static int rd_offset;
static int num_tx;

static inline int need_next_slot(uint16_t flags)
{
	return (flags & NS_MOREFRAG);
}

/* ukvm net interface */
int solo5_net_write_sync(uint8_t *data, int n)
{
    int ret = 0;
	char *addr = (char *)data;

	/* Check if the TX ring has enough data buffer */
	int slots_available = (int)nm_ring_space(&tx);
	int available = slots_available * tx.nr_buf_size;
	if (n > available) {
		log(1, "TX ring#0 does not have enough buffer size\n");
		ret = -1;
		goto out;
	}

	/* Try to fill slots */
	uint32_t cur = *tx.cur;
	size_t i;
	size_t count = n / (size_t)tx.nr_buf_size;
	size_t last = n % (size_t)tx.nr_buf_size;
	for(i = 0; i < count; i++){
		struct netmap_slot *slot = &tx.slot[cur];
		char *nm_buf = NETMAP_BUF(tx, slot->buf_idx - tx.index_offset);
		//printf("nm_buf = %p, buf_idx = %d\n", nm_buf, slot->buf_idx);
		memcpy(nm_buf, addr, tx.nr_buf_size);
		slot->len = tx.nr_buf_size;
		cur = nm_ring_next(&tx, cur);
		addr += tx.nr_buf_size;
	}
	struct netmap_slot *slot = &tx.slot[cur];
	char *nm_buf = NETMAP_BUF(tx, slot->buf_idx - tx.index_offset);
	//printf("nm_buf = %p, buf_idx = %d\n", nm_buf, slot->buf_idx);
	memcpy(nm_buf, addr, last);
	slot->len = last;
	cur = nm_ring_next(&tx, cur);

	*tx.head = *tx.cur = cur;

	/* Send packets and update the ring indexes */
	num_tx++;
	if ((num_tx % 64) == 0) {
    	volatile int tx_ret;
    	ukvm_do_hypercall(UKVM_HYPERCALL_NETMAPWRITE, &tx_ret);
		ret = tx_ret;
		num_tx = 0;
	}

	/* TODO: need TX completion polling? */
	/*
	while(nm_tx_pending(txring)){
	}
	*/
	
out:
	return ret;
}

int solo5_net_read_sync(uint8_t *data, int *n)
{
	/*
	 * We don't use NIOCRXSYNC ioctl to update the ring indexes
	 * because they are automatically updated in ppoll() on ukvm(the host OS) side
	 */

    int ret = 0;

	size_t to_read = (size_t)nm_ring_space(&rx);
	if (to_read == 0) {
		//warnx("No data on the RX queue#0");
		ret = -1;
		goto out;
	}

	/* Read from the RX buffer */
	int rd_len = *n;
	int n_read = 0;
	uint32_t cur = *rx.cur;
	char *addr = (char *)data;
	for (; to_read > 0; to_read--) {
		struct netmap_slot *slot = &rx.slot[cur];
		char *nm_buf = NETMAP_BUF(rx, slot->buf_idx - rx.index_offset);

		if (rd_offset == 0) {
			if (n_read + (int)(slot->len) > rd_len) {
				int left = rd_len - n_read;
				memcpy(addr, nm_buf, left);
				n_read += left;
				rd_offset = left;
				break ;
			} else {
				memcpy(addr, nm_buf, slot->len);
				n_read += slot->len;
				addr += slot->len;
				cur = nm_ring_next(&rx, cur);
				if(!need_next_slot(slot->flags))
					break ;
			}
		} else {
			if ((int)(slot->len) - rd_offset > rd_len) {
				memcpy(addr, nm_buf + rd_offset, rd_len);
				n_read += rd_len;
				rd_offset += rd_len;
				break ;
			} else {
				size_t left = slot->len - rd_offset;
				memcpy(addr, nm_buf + rd_offset, left);
				n_read += left;
				addr += left;
				cur = nm_ring_next(&rx, cur);
				rd_offset = 0;
				if(!need_next_slot(slot->flags))
					break ;
			}
		}
	}
	*rx.head = *rx.cur = cur;
	*n = n_read;

out:
	return ret;
}

int solo5_netmap_get_ringinfo(struct ukvm_netmap_ringinfo *i)
{
	volatile struct ukvm_netmap_ringinfo tmp;

    ukvm_do_hypercall(UKVM_HYPERCALL_NETMAP_RINGINFO, &tmp);
	memcpy(i, (void *)&tmp, sizeof(struct ukvm_netmap_ringinfo));

	return tmp.ret;
}

static char mac_str[18];
char *solo5_net_mac_str(void)
{
    volatile struct ukvm_netinfo info;

    ukvm_do_hypercall(UKVM_HYPERCALL_NETMAPINFO, &info);

    memcpy(mac_str, (void *)&info, 18);
    return mac_str;
}

void configure_netmap_rings(void)
{
	if (solo5_netmap_get_ringinfo(&ringinfo) == -1){
		log(1, "Netmap ring configuration error.");
	}

	/* RX ring */
	rx.buf_base = (char *)ringinfo.rx.buf_base;
	rx.num_slots = ringinfo.rx.num_slots;
	rx.nr_buf_size = ringinfo.rx.nr_buf_size;
	rx.head = (uint32_t *)ringinfo.rx.head_addr;
	rx.cur = (uint32_t *)ringinfo.rx.cur_addr;
	rx.tail = (uint32_t *)ringinfo.rx.tail_addr;
	rx.slot = (struct netmap_slot *)ringinfo.rx.slot_base;
	rx.index_offset = ringinfo.rx.index_offset;

	/* TX ring */
	tx.buf_base = (char *)ringinfo.tx.buf_base;
	tx.num_slots = ringinfo.tx.num_slots;
	tx.nr_buf_size = ringinfo.tx.nr_buf_size;
	tx.head = (uint32_t *)ringinfo.tx.head_addr;
	tx.cur = (uint32_t *)ringinfo.tx.cur_addr;
	tx.tail = (uint32_t *)ringinfo.tx.tail_addr;
	tx.slot = (struct netmap_slot *)ringinfo.tx.slot_base;
	tx.index_offset = ringinfo.tx.index_offset;

	rd_offset = 0;
	num_tx = 0;

	return ;
}

void net_init(void)
{
}
