/*
 * Copyright (C) 2011-2016 Universita` di Pisa
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * struct netmap_slot is a buffer descriptor
 */
struct netmap_slot {
	uint32_t buf_idx;	/* buffer index */
	uint16_t len;		/* length for this slot */
	uint16_t flags;		/* buf changed, etc. */
	uint64_t ptr;		/* pointer for indirect buffers */
};

struct ukvm_netmap_guestring{
	char *buf_base;
	uint32_t num_slots;
	uint32_t nr_buf_size;

	uint32_t *head;
	uint32_t *cur;
	uint32_t *tail;

	struct netmap_slot *slot;

	uint32_t index_offset;
};

static inline uint32_t
nm_ring_next(struct ukvm_netmap_guestring *ring, uint32_t i)
{
	//return ( unlikely(i + 1 == num_slots) ? 0 : i + 1);
	return ((i + 1) % ring->num_slots);
}

static inline int
nm_ring_empty(struct ukvm_netmap_guestring *ring)
{
	return (*ring->cur == *ring->tail);
}
	
static inline uint32_t
nm_ring_space(struct ukvm_netmap_guestring *ring)
{
    int ret = *ring->tail - *ring->cur;
    if (ret < 0)
        ret += ring->num_slots;
    return ret;
}

#define NETMAP_BUF(ring, index)				\
	(ring.buf_base + ((index)*ring.nr_buf_size))

#define NS_MOREFRAG 0x0020
