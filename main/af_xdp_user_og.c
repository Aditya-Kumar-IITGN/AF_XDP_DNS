#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "resolver_og.c"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX
#define MAX_WORKER_THREADS 10
#define MAX_PENDING_QUERIES 100

// extern char *resolve_dns(uint16_t tx_id, const char *domain_name, int rec_desired);

/* Work queue structures for multithreading */
struct dns_work_item {
	uint8_t *packet_data;
	uint32_t packet_len;
	uint64_t addr;
	struct xsk_socket_info *xsk;
	char domain_name[256];
	uint16_t dns_id;
	int recursion_desired;
	struct dns_work_item *next;
};

struct work_queue {
	struct dns_work_item *head;
	struct dns_work_item *tail;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int count;
	int shutdown;
};

/* Thread pool structure */
struct thread_pool {
	pthread_t workers[MAX_WORKER_THREADS];
	struct work_queue queue;
	int num_threads;
	int active;
};

static struct xdp_program *prog;
int xsk_map_fd;
bool custom_xsk = false;
static bool global_exit;

struct config cfg = {
	.ifindex   = -1,
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct stats_record {
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
};

struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

/* Function to extract domain name from DNS question section */
static int extract_domain_name(uint8_t *dns_payload, char *domain_name, int max_len) {
	uint8_t *ptr = dns_payload;
	int pos = 0;
	int jumped = 0;
	int original_pos = 0;
	
	while (*ptr != 0) {
		if ((*ptr & 0xC0) == 0xC0) {
			/* Compression pointer */
			if (!jumped) {
				original_pos = ptr - dns_payload + 2;
			}
			jumped = 1;
			ptr = dns_payload + (ntohs(*(uint16_t*)ptr) & 0x3FFF);
		} else {
			/* Regular label */
			int label_len = *ptr++;
			if (pos + label_len + 1 >= max_len) {
				return -1; /* Buffer too small */
			}
			
			if (pos > 0) {
				domain_name[pos++] = '.';
			}
			
			for (int i = 0; i < label_len; i++) {
				domain_name[pos++] = *ptr++;
			}
		}
	}
	
	domain_name[pos] = '\0';
	
	if (jumped) {
		return original_pos;
	} else {
		return ptr - dns_payload + 1; /* +1 for the null terminator */
	}
}

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help",	 no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",	 required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",	 no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",	 no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",	 no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"copy",        no_argument,		NULL, 'c' },
	 "Force copy mode"},

	{{"zero-copy",	 no_argument,		NULL, 'z' },
	 "Force zero-copy mode"},

	{{"queue",	 required_argument,	NULL, 'Q' },
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode",	 no_argument,		NULL, 'p' },
	 "Use the poll() API waiting for packets to arrive"},

	{{"quiet",	 no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",	 required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
						    struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;
	uint32_t prog_id;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: 0;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);
	if (ret)
		goto error_exit;

	if (custom_xsk) {
		ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
		if (ret)
			goto error_exit;
	} else {
		/* Getting the program ID must be after the xdp_socket__create() call */
		if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
			goto error_exit;
	}

	/* Initialize umem frame allocation */
	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
					XSK_RING_CONS__DEFAULT_NUM_DESCS,
					&idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(xsk,
					    *xsk_ring_cons__comp_addr(&xsk->umem->cq,
								      idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
			completed : xsk->outstanding_tx;
	}
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

static inline unsigned short ip_csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

bool craft_response(uint8_t *pkt, uint8_t *tmp_mac, __be32 *tmp_ip, uint32_t *new_len) {
	/* Extract DNS header */
	struct ethhdr *eth = (struct ethhdr *) pkt;
	struct iphdr *ip = (struct iphdr *) (eth + 1); /* Renamed to 'ip' */
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
	struct dnshdr *dns = (struct dnshdr *)((void *)udp + sizeof(*udp));

	// printf("DNS packet: ID=0x%04x Flags=0x%04x Questions=%d Answers=%d\n",
		//    ntohs(dns->id), ntohs(dns->flags), ntohs(dns->qdcount), ntohs(dns->ancount));

	/* Only respond to DNS queries (not responses) */
	if (ntohs(dns->flags) & 0x8000) {
		/* This is already a response, don't process */
		return false;
	}

	/* Extract and log the domain name from the question section */
	char domain_name[256];
	uint8_t *dns_payload = (uint8_t *)(dns + 1);
	int name_len = extract_domain_name(dns_payload, domain_name, sizeof(domain_name));
	
	if (name_len > 0) {
		// printf("DNS Query for domain: %s\n", domain_name);
	} else {
		// printf("Failed to extract domain name\n");
		return false;
	}

	/* Create DNS response packet with dummy answer */

	/* Swap MAC addresses */
	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	/* Swap IP addresses */
	*tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = *tmp_ip;

	/* Swap UDP ports */
	uint16_t tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

	/* Modify DNS header to make it a response */
	dns->flags = htons(0x8180); /* Response, Recursion Available, No Error */
	dns->ancount = htons(1);    /* 1 Answer */
	dns->nscount = htons(0);    /* 0 Authority RRs */
	dns->arcount = htons(0);    /* 0 Additional RRs */

	/* Calculate where the answer section should start */
	/* Skip the question section - we need to parse the original question */
	uint8_t *question_ptr = (uint8_t *)(dns + 1);
	
	/* Skip the domain name in the question (ends with null byte) */
	while (*question_ptr != 0) {
		if ((*question_ptr & 0xC0) == 0xC0) {
			/* Compressed name - skip 2 bytes */
			question_ptr += 2;
			break;
		} else {
			/* Regular label - skip length + label */
			question_ptr += *question_ptr + 1;
		}
	}
	if (*question_ptr == 0) question_ptr++; /* Skip final null byte */

    uint16_t tx_id = rand() & 0xFFFF;

	char *resolved_ip = resolve_dns(tx_id, domain_name, 0);

	/* Skip QTYPE (2 bytes) and QCLASS (2 bytes) */
	question_ptr += 4;
	
	/* Now question_ptr points to where we should add the answer */
	uint8_t *answer_ptr = question_ptr;
	
	/* Add DNS Answer Record */
	/* Name compression pointer back to the question name */
	*answer_ptr++ = 0xC0;  /* Compression flag */
	*answer_ptr++ = 0x0C;  /* Offset to question name (after DNS header) */
	
	/* TYPE: A record (IPv4 address) */
	*answer_ptr++ = 0x00;
	*answer_ptr++ = 0x01;
	
	/* CLASS: IN (Internet) */
	*answer_ptr++ = 0x00;
	*answer_ptr++ = 0x01;
	
	/* TTL: 300 seconds */
	*answer_ptr++ = 0x00;
	*answer_ptr++ = 0x00;
	*answer_ptr++ = 0x01;
	*answer_ptr++ = 0x2C;
	
	/* RDLENGTH: 4 bytes (IPv4 address) */
	*answer_ptr++ = 0x00;
	*answer_ptr++ = 0x04;

	/* Convert IP address string to 4 bytes */
	if (resolved_ip) {
		struct in_addr addr;
		if (inet_aton(resolved_ip, &addr) == 1) {
			uint32_t ip_addr = ntohl(addr.s_addr);
			*answer_ptr++ = (ip_addr >> 24) & 0xFF;
			*answer_ptr++ = (ip_addr >> 16) & 0xFF;
			*answer_ptr++ = (ip_addr >> 8) & 0xFF;
			*answer_ptr++ = ip_addr & 0xFF;
		}
		free(resolved_ip);
	} else {
		// printf("Oh nooooo, idk didn't return anything");
		return false;
	}
	
	/* Calculate new packet length */
	*new_len = (answer_ptr - pkt);
	
	/* Update UDP length */
	udp->len = htons(*new_len - sizeof(*eth) - sizeof(*ip));
	
	/* Update IP total length */
	ip->tot_len = htons(*new_len - sizeof(*eth));
	
	/* Recalculate IP checksum */
	ip->check = 0;
	ip->check = ip_csum((unsigned short *)ip, ip->ihl * 2);
	
	/* Recalculate UDP checksum (set to 0 for simplicity) */
	udp->check = 0;
	return true;
}

/* Global thread pool */
static struct thread_pool dns_thread_pool;

/* Work queue management functions */
static void work_queue_init(struct work_queue *queue) {
	queue->head = NULL;
	queue->tail = NULL;
	queue->count = 0;
	queue->shutdown = 0;
	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->cond, NULL);
}


/* Function to send DNS response */
static int send_dns_response(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len) {
	uint32_t tx_idx = 0;
	int ret;
	
	/* Reserve slot in TX ring and send packet */
	ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	if (ret != 1) {
		/* No more transmit slots, drop the packet */
		// printf("Failed to reserve TX slot\n");
		return -1;
	}
	
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
	xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
	xsk_ring_prod__submit(&xsk->tx, 1);
	xsk->outstanding_tx++;
	
	/* Trigger kernel to send the packet */
	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret < 0 && errno != ENOBUFS && errno != EAGAIN) {
		// printf("Failed to trigger kernel send: %s\n", strerror(errno));
	}
	
	xsk->stats.tx_bytes += len;
	xsk->stats.tx_packets++;
	
	// printf("Queued packet for transmission: addr=0x%lx, len=%u\n", addr, len);
	return 0;
}

/* Modified craft_response function for use with resolved IP */
static bool craft_response_with_ip(uint8_t *pkt, const char *resolved_ip, uint32_t *new_len) {
	/* Extract DNS header */
	struct ethhdr *eth = (struct ethhdr *) pkt;
	struct iphdr *ip = (struct iphdr *) (eth + 1);
	struct udphdr *udp = (void *)ip + (ip->ihl * 4);
	struct dnshdr *dns = (struct dnshdr *)((void *)udp + sizeof(*udp));
	
	/* Swap MAC addresses */
	uint8_t tmp_mac[ETH_ALEN];
	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);
	
	/* Swap IP addresses */
	__be32 tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;
	
	/* Swap UDP ports */
	uint16_t tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;
	
	/* Modify DNS header to make it a response */
	dns->flags = htons(0x8180);
	dns->ancount = htons(1);
	dns->nscount = htons(0);
	dns->arcount = htons(0);
	
	/* Calculate where the answer section should start */
	uint8_t *question_ptr = (uint8_t *)(dns + 1);
	
	/* Skip the domain name in the question */
	while (*question_ptr != 0) {
		if ((*question_ptr & 0xC0) == 0xC0) {
			question_ptr += 2;
			break;
		} else {
			question_ptr += *question_ptr + 1;
		}
	}
	if (*question_ptr == 0) question_ptr++;
	
	/* Skip QTYPE and QCLASS */
	question_ptr += 4;
	
	/* Add answer record */
	uint8_t *answer_ptr = question_ptr;
	*answer_ptr++ = 0xC0;
	*answer_ptr++ = 0x0C;
	*answer_ptr++ = 0x00; *answer_ptr++ = 0x01; /* TYPE A */
	*answer_ptr++ = 0x00; *answer_ptr++ = 0x01; /* CLASS IN */
	*answer_ptr++ = 0x00; *answer_ptr++ = 0x00; /* TTL high */
	*answer_ptr++ = 0x01; *answer_ptr++ = 0x2C; /* TTL low (300 sec) */
	*answer_ptr++ = 0x00; *answer_ptr++ = 0x04; /* RDLENGTH */
	
	/* Convert IP address string to bytes */
	struct in_addr addr;
	if (inet_aton(resolved_ip, &addr) == 1) {
		uint32_t ip_addr = ntohl(addr.s_addr);
		*answer_ptr++ = (ip_addr >> 24) & 0xFF;
		*answer_ptr++ = (ip_addr >> 16) & 0xFF;
		*answer_ptr++ = (ip_addr >> 8) & 0xFF;
		*answer_ptr++ = ip_addr & 0xFF;
	} else {
		return false;
	}
	
	/* Calculate new packet length */
	*new_len = (answer_ptr - pkt);
	
	/* Update UDP and IP lengths */
	udp->len = htons(*new_len - sizeof(*eth) - sizeof(*ip));
	ip->tot_len = htons(*new_len - sizeof(*eth));
	
	/* Recalculate checksums */
	ip->check = 0;
	ip->check = ip_csum((unsigned short *)ip, ip->ihl * 2);
	udp->check = 0;
	
	return true;
}

/* Function to craft DNS error response */
static bool craft_error_response(uint8_t *pkt, uint32_t *new_len, uint16_t rcode) {
	/* Extract DNS header */
	struct ethhdr *eth = (struct ethhdr *) pkt;
	struct iphdr *ip = (struct iphdr *) (eth + 1);
	struct udphdr *udp = (void *)ip + (ip->ihl * 4);
	struct dnshdr *dns = (struct dnshdr *)((void *)udp + sizeof(*udp));
	
	/* Swap MAC addresses */
	uint8_t tmp_mac[ETH_ALEN];
	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);
	
	/* Swap IP addresses */
	__be32 tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;
	
	/* Swap UDP ports */
	uint16_t tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;
	
	/* Modify DNS header to make it an error response */
	dns->flags = htons(0x8180|rcode); /* 0x8180 = Response + Recursion Available. We add the rcode. */
	dns->ancount = htons(0);    /* 0 Answers */
	dns->nscount = htons(0);    /* 0 Authority RRs */
	dns->arcount = htons(0);    /* 0 Additional RRs */
	
	/* Calculate packet length (no answer section added) */
	uint8_t *question_ptr = (uint8_t *)(dns + 1);
	
	/* Skip the domain name in the question */
	while (*question_ptr != 0) {
		if ((*question_ptr & 0xC0) == 0xC0) {
			question_ptr += 2;
			break;
		} else {
			question_ptr += *question_ptr + 1;
		}
	}
	if (*question_ptr == 0) question_ptr++;
	
	/* Skip QTYPE and QCLASS */
	question_ptr += 4;
	
	/* Calculate new packet length (just up to end of question) */
	*new_len = (question_ptr - pkt);
	
	/* Update UDP and IP lengths */
	udp->len = htons(*new_len - sizeof(*eth) - sizeof(*ip));
	ip->tot_len = htons(*new_len - sizeof(*eth));
	
	/* Recalculate checksums */
	ip->check = 0;
	ip->check = ip_csum((unsigned short *)ip, ip->ihl * 2);
	udp->check = 0;
	
	return true;
}

static void work_queue_destroy(struct work_queue *queue) {
	pthread_mutex_lock(&queue->mutex);
	queue->shutdown = 1;
	pthread_cond_broadcast(&queue->cond);
	pthread_mutex_unlock(&queue->mutex);
	
	/* Free remaining work items */
	struct dns_work_item *item = queue->head;
	while (item) {
		struct dns_work_item *next = item->next;
		/* Free the frame since we're shutting down */
		if (item->xsk && item->addr != INVALID_UMEM_FRAME) {
			xsk_free_umem_frame(item->xsk, item->addr);
		}
		free(item);
		item = next;
	}
	
	pthread_mutex_destroy(&queue->mutex);
	pthread_cond_destroy(&queue->cond);
}

static int work_queue_push(struct work_queue *queue, struct dns_work_item *item) {
	pthread_mutex_lock(&queue->mutex);
	
	if (queue->count >= MAX_PENDING_QUERIES) {
		pthread_mutex_unlock(&queue->mutex);
		return -1; /* Queue full */
	}
	
	item->next = NULL;
	if (queue->tail) {
		queue->tail->next = item;
	} else {
		queue->head = item;
	}
	queue->tail = item;
	queue->count++;
	
	pthread_cond_signal(&queue->cond);
	pthread_mutex_unlock(&queue->mutex);
	return 0;
}

static struct dns_work_item *work_queue_pop(struct work_queue *queue) {
	pthread_mutex_lock(&queue->mutex);
	
	while (queue->head == NULL && !queue->shutdown) {
		pthread_cond_wait(&queue->cond, &queue->mutex);
	}
	
	if (queue->shutdown) {
		pthread_mutex_unlock(&queue->mutex);
		return NULL;
	}
	
	struct dns_work_item *item = queue->head;
	queue->head = item->next;
	if (queue->head == NULL) {
		queue->tail = NULL;
	}
	queue->count--;
	
	pthread_mutex_unlock(&queue->mutex);
	return item;
}

/* Worker thread function */
static void *dns_worker_thread(void *arg) {
	struct thread_pool *pool = (struct thread_pool *)arg;
	
	// printf("DNS worker thread started\n");
	
	while (1) {
		struct dns_work_item *item = work_queue_pop(&pool->queue);
		if (!item) {
			break; /* Shutdown */
		}
		
		// printf("Processing DNS query for: %s\n", item->domain_name);
		
		/* Perform DNS resolution */
		uint16_t tx_id = rand() & 0xFFFF;
		char *resolved_ip = resolve_dns(tx_id, item->domain_name, 0);
		// char *resolved_ip = resolve_dns(tx_id, item->domain_name, item->recursion_desired);
		
		uint8_t *original_pkt = xsk_umem__get_data(item->xsk->umem->buffer, item->addr);
		uint32_t new_len;
		
		if (resolved_ip == nxdomain_signal) {
			/* (NXDOMAIN) */
			/* The resolver confirmed the domain does not exist. */
			// printf("Failed to resolve %s (NXDOMAIN), sending error response\n", item->domain_name);
			
			if (craft_error_response(original_pkt, &new_len, 3)) { // RCODE 3 = NXDOMAIN
				if (send_dns_response(item->xsk, item->addr, new_len) == 0) {
					// printf("Successfully sent DNS error response for %s\n", item->domain_name);
					complete_tx(item->xsk);
				} else {
					// printf("Failed to send DNS error response for %s\n", item->domain_name);
					xsk_free_umem_frame(item->xsk, item->addr);
				}
			} else {
				// printf("Failed to create DNS error response for %s\n", item->domain_name);
				xsk_free_umem_frame(item->xsk, item->addr);
			}

		} else if (resolved_ip != NULL) {
			// printf("Resolved %s to %s\n", item->domain_name, resolved_ip);
			
			if (craft_response_with_ip(original_pkt, resolved_ip, &new_len)) {
				if (send_dns_response(item->xsk, item->addr, new_len) == 0) {
					// printf("Successfully queued DNS response for %s\n", item->domain_name);
					complete_tx(item->xsk);
				} else {
					// printf("Failed to send DNS response for %s\n", item->domain_name);
					xsk_free_umem_frame(item->xsk, item->addr);
				}
			} else {
				// printf("Failed to create success response packet for %s, sending SERVFAIL\n", item->domain_name);
				uint32_t error_len;
				if (craft_error_response(original_pkt, &error_len, 2)) { // RCODE 2 = SERVFAIL
					if (send_dns_response(item->xsk, item->addr, error_len) == 0) {
						complete_tx(item->xsk);
					} else {
						xsk_free_umem_frame(item->xsk, item->addr);
					}
				} else {
					xsk_free_umem_frame(item->xsk, item->addr);
				}
			}
			
			free(resolved_ip); // This is a real, malloc'd IP string

		} else {
			/* (NULL) */
			/* The resolver timed out or failed. This is our fault (SERVFAIL). */
			// printf("Failed to resolve %s (timeout/SERVFAIL), sending error response\n", item->domain_name);
			
			if (craft_error_response(original_pkt, &new_len, 2)) { // RCODE 2 = SERVFAIL
				if (send_dns_response(item->xsk, item->addr, new_len) == 0) {
					// printf("Successfully sent DNS SERVFAIL response for %s\n", item->domain_name);
					complete_tx(item->xsk);
				} else {
					// printf("Failed to send DNS SERVFAIL response for %s\n", item->domain_name);
					xsk_free_umem_frame(item->xsk, item->addr);
				}
			} else {
				// printf("Failed to create DNS SERVFAIL response for %s\n", item->domain_name);
				xsk_free_umem_frame(item->xsk, item->addr);
			}
		}
		
		/* Cleanup */
		free(item);
	}
	
	// printf("DNS worker thread exiting\n");
	return NULL;
}

/* Thread pool management */
static int thread_pool_init(struct thread_pool *pool, int num_threads) {
	if (num_threads > MAX_WORKER_THREADS) {
		num_threads = MAX_WORKER_THREADS;
	}
	
	pool->num_threads = num_threads;
	pool->active = 1;
	work_queue_init(&pool->queue);
	
	/* Create worker threads */
	for (int i = 0; i < num_threads; i++) {
		if (pthread_create(&pool->workers[i], NULL, dns_worker_thread, pool) != 0) {
			// fprintf(stderr, "Failed to create worker thread %d\n", i);
			return -1;
		}
	}
	
	// printf("Created %d DNS worker threads\n", num_threads);
	return 0;
}

static void thread_pool_destroy(struct thread_pool *pool) {
	pool->active = 0;
	work_queue_destroy(&pool->queue);
	
	/* Wait for all threads to finish */
	for (int i = 0; i < pool->num_threads; i++) {
		pthread_join(pool->workers[i], NULL);
	}
	
	// printf("All DNS worker threads terminated\n");
}

static bool process_packet(struct xsk_socket_info *xsk,
			   uint64_t addr, uint32_t len)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

	/* Process DNS packets */
	// printf("Processing packet\n");
	struct ethhdr *eth = (struct ethhdr *) pkt;
	struct iphdr *ip = (struct iphdr *) (eth + 1);
	struct udphdr *udp = (void *)ip + (ip->ihl * 4);

	// printf("Destination %d, source %d\n", ntohs(udp->dest), ntohs(udp->source));

	/* Check if this is a UDP packet on port 53 (DNS) */
	if (ntohs(eth->h_proto) != ETH_P_IP ||
		len < (sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dnshdr)) ||
		ip->protocol != IPPROTO_UDP ||
		(udp->dest != __constant_htons(53) && udp->source != __constant_htons(53)))
		return false;

	/* Extract DNS header and domain name */
	struct dnshdr *dns = (struct dnshdr *)((void *)udp + sizeof(*udp));
	
	/* Only process DNS queries (not responses) */
	if (ntohs(dns->flags) & 0x8000) {
		return false;
	}

	/* Extract domain name */
	char domain_name[256];
	uint8_t *dns_payload = (uint8_t *)(dns + 1);
	int name_len = extract_domain_name(dns_payload, domain_name, sizeof(domain_name));
	
	if (name_len <= 0) {
		// printf("Failed to extract domain name\n");
		return false;
	}

	int recursion_desired = (ntohs(dns->flags) & 0x0100) ? 1 : 0;

	// printf("DNS Query for domain: %s (queuing for async resolution)\n", domain_name);

	/* Create work item for thread pool */
	struct dns_work_item *work_item = malloc(sizeof(struct dns_work_item));
	if (!work_item) {
		// printf("Failed to allocate work item\n");
		return false;
	}
	
	/* We don't need to copy packet data, just store the frame info */
	work_item->packet_data = NULL; /* Not used anymore */
	work_item->packet_len = len;
	work_item->addr = addr;
	work_item->xsk = xsk;
	strcpy(work_item->domain_name, domain_name);
	work_item->dns_id = ntohs(dns->id);
	work_item->recursion_desired = recursion_desired;
	
	/* Submit to thread pool */
	if (work_queue_push(&dns_thread_pool.queue, work_item) != 0) {
		// printf("Work queue full, dropping query\n");
		free(work_item);
		return false;
	}
	
	/* Don't free the frame yet - it will be freed by the worker thread */
	return true;
}

static void handle_receive_packets(struct xsk_socket_info *xsk)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
					xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		if (!process_packet(xsk, addr, len))
			xsk_free_umem_frame(xsk, addr);

		xsk->stats.rx_bytes += len;
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->stats.rx_packets += rcvd;

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk);
  }

static void rx_and_process(struct config *cfg,
			   struct xsk_socket_info *xsk_socket)
{
	struct pollfd fds[2];
	int ret, nfds = 1;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while(!global_exit) {
		if (cfg->xsk_poll_mode) {
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		handle_receive_packets(xsk_socket);
	}
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		// fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	uint64_t packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */

	char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
		" %'11lld Kbytes (%'6.0f Mbits/s)"
		" period:%f\n";

	period = calc_period(stats_rec, stats_prev);
	if (period == 0)
		period = 1;

	packets = stats_rec->rx_packets - stats_prev->rx_packets;
	pps     = packets / period;

	bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	// printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
	    //    stats_rec->rx_bytes / 1000 , bps,
	    //    period);

	packets = stats_rec->tx_packets - stats_prev->tx_packets;
	pps     = packets / period;

	bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
	bps     = (bytes * 8) / period / 1000000;

	// printf(fmt, "       TX:", stats_rec->tx_packets, pps,
	    //    stats_rec->tx_bytes / 1000 , bps,
	    //    period);

	// printf("\n");
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct xsk_socket_info *xsk = arg;
	static struct stats_record previous_stats = { 0 };

	previous_stats.timestamp = gettime();

	/* Trick to pretty // printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit) {
		sleep(interval);
		xsk->stats.timestamp = gettime();
		stats_print(&xsk->stats, &previous_stats);
		previous_stats = xsk->stats;
	}
	return NULL;
}

static void exit_application(int signal)
{
	int err;

	cfg.unload_all = true;
	err = do_unload(&cfg);
	if (err) {
		// fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n",
		// 	cfg.ifname, err);
	}

	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
    srand(time(NULL));

	int ret;
	void *packet_buffer;
	uint64_t packet_buffer_size;
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	int err;
	char errmsg[1024];

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		// fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Load custom program if configured */
	if (cfg.filename[0] != 0) {
		DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
			.open_filename = cfg.filename,
		);
		struct bpf_map *map;
		custom_xsk = true;
		if (cfg.progname[0] != 0)
			xdp_opts.prog_name = cfg.progname;

		prog = xdp_program__create(&xdp_opts);
		err = libxdp_get_error(prog);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			// fprintf(stderr, "ERR: loading program: %s\n", errmsg);
			return err;
		}

		err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			// fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			// 	cfg.ifname, errmsg, err);
			return err;
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
		xsk_map_fd = bpf_map__fd(map);
		if (xsk_map_fd < 0) {
			// fprintf(stderr, "ERROR: no xsks map found: %s\n",
			// 	strerror(xsk_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 *
	 * NOTE: since kernel v5.11, eBPF maps allocations are not tracked
	 * through the process anymore. Now, eBPF maps are accounted to the
	 * current cgroup of which the process that created the map is part of
	 * (assuming the kernel was built with CONFIG_MEMCG).
	 *
	 * Therefore, you should ensure an appropriate memory.max setting on
	 * the cgroup (via sysfs, for example) instead of relying on rlimit.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		// fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
		// 	strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		// fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
		// 	strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		// fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
		// 	strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL) {
		// fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
		// 	strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize DNS thread pool */
	if (thread_pool_init(&dns_thread_pool, MAX_WORKER_THREADS) != 0) {
		// fprintf(stderr, "ERROR: Failed to initialize DNS thread pool\n");
		exit(EXIT_FAILURE);
	}

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, xsk_socket);

	/* Cleanup */
	// printf("Shutting down DNS thread pool...\n");
	thread_pool_destroy(&dns_thread_pool);
	
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);
	free(packet_buffer);

	return EXIT_OK;
}
