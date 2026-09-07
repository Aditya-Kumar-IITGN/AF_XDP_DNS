#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>

#define CACHE_SIZE 1024
#define CACHE_TTL 300 // seconds
#define HASH_BUCKETS 1024


typedef struct dns_cache_node {
    char domain[256];
    unsigned char *response;
    size_t resp_len;
    time_t expiry;

    // Doubly linked list for LRU tracking
    struct dns_cache_node *prev;
    struct dns_cache_node *next;

    // Singly linked list for hash collisions
    struct dns_cache_node *h_next;
} dns_cache_node;

static dns_cache_node *hashtable[HASH_BUCKETS];
static dns_cache_node *lru_head = NULL;
static dns_cache_node *lru_tail = NULL;
static int cache_count = 0;

static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;

//djb2 hash
static unsigned int hash_domain(const char *s)
{
    unsigned int h = 5381;
    while (*s)
        h = ((h << 5) + h) + (unsigned char)(*s++);
    return h % HASH_BUCKETS;
}

static void lru_promote(dns_cache_node *node)
{
    if (node == lru_head) return; 

    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
    if (node == lru_tail) lru_tail = node->prev;

    // Attach to head
    node->next = lru_head;
    node->prev = NULL;
    if (lru_head) lru_head->prev = node;
    lru_head = node;

    if (!lru_tail) lru_tail = node;
}

static void lru_evict()
{
    if (!lru_tail) return;

    dns_cache_node *victim = lru_tail;

    if (victim->prev) victim->prev->next = NULL;
    lru_tail = victim->prev;
    if (lru_head == victim) lru_head = NULL;

    unsigned int h = hash_domain(victim->domain);
    dns_cache_node *curr = hashtable[h];
    dns_cache_node *prev_h = NULL;

    while (curr) {
        if (curr == victim) {
            if (prev_h) prev_h->h_next = curr->h_next;
            else hashtable[h] = curr->h_next;
            break;
        }
        prev_h = curr;
        curr = curr->h_next;
    }

    if (victim->response) free(victim->response);
    free(victim);
    cache_count--;
    // printf("DEBUG: Evicted %s\n", victim->domain);
}


void cache_store(const char *domain, const char *ip_or_signal)
{
    if (!domain || !ip_or_signal) return;

    pthread_mutex_lock(&cache_lock);

    unsigned int h = hash_domain(domain);
    dns_cache_node *node = hashtable[h];

    while (node) {
        if (strcmp(node->domain, domain) == 0) {
            // Found existing: update it
            if (node->response) free(node->response);
            node->resp_len = strlen(ip_or_signal) + 1;
            node->response = malloc(node->resp_len);
            if (node->response) {
                memcpy(node->response, ip_or_signal, node->resp_len);
            }
            node->expiry = time(NULL) + CACHE_TTL;
            lru_promote(node);
            pthread_mutex_unlock(&cache_lock);
            return;
        }
        node = node->h_next;
    }

    // Not found. Evict if full before creating new.
    if (cache_count >= CACHE_SIZE) {
        lru_evict();
    }

    node = malloc(sizeof(dns_cache_node));
    if (!node) {
        pthread_mutex_unlock(&cache_lock);
        return; // Out of memory
    }

    strncpy(node->domain, domain, sizeof(node->domain) - 1);
    node->domain[sizeof(node->domain) - 1] = '\0';
    node->resp_len = strlen(ip_or_signal) + 1;
    node->response = malloc(node->resp_len);
    if (node->response) {
        memcpy(node->response, ip_or_signal, node->resp_len);
    }
    node->expiry = time(NULL) + CACHE_TTL;

    // Insert into hash bucket (at front of bucket list is fine)
    node->h_next = hashtable[h];
    hashtable[h] = node;

    // Insert into LRU list (at head)
    node->next = lru_head;
    node->prev = NULL;
    if (lru_head) lru_head->prev = node;
    lru_head = node;
    if (!lru_tail) lru_tail = node;

    cache_count++;

    pthread_mutex_unlock(&cache_lock);
}

char *cache_lookup_exact(const char *domain)
{
    if (!domain) return NULL;

    unsigned int h = hash_domain(domain);

    pthread_mutex_lock(&cache_lock);

    dns_cache_node *node = hashtable[h];
    while (node) {
        if (strcmp(node->domain, domain) == 0) {
            if (time(NULL) < node->expiry && node->response) {
                lru_promote(node); 
                char *ret = strdup((char *)node->response);
                pthread_mutex_unlock(&cache_lock);
                return ret;
            } else {
                // Expired. We could evict it here, but let standard eviction handle it later
                // or let a new store overwrite it. For simplicity, just treat as miss.
            }
            break; 
        }
        node = node->h_next;
    }

    pthread_mutex_unlock(&cache_lock);
    return NULL;
}


#define DNS_PORT 53
#define BUFFER_SIZE 512
#define QUERY_TIMEOUT_SEC 3

const char *ROOT_NAME_SERVERS[] = {
    "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33", NULL};

static char nxdomain_signal[] = "NXDOMAIN";

#pragma pack(push, 1)
struct DNSHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct DNSQuestionTail
{
    uint16_t qtype;
    uint16_t qclass;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ResourceRecordTail
{
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
};
#pragma pack(pop)

char *resolve_dns_recursive(uint16_t tx_id, const char *domain_name, const char *server_ip, int rec_desired, int depth);
char *resolve_dns(uint16_t tx_id, const char *domain_name, int rec_desired);
void format_domain_name(const char *domain, char *output);
int parse_domain_name(unsigned char *buffer, unsigned char *dns_start, char *output);
int local_strcasecmp(const char *s1, const char *s2);

int local_strcasecmp(const char *s1, const char *s2)
{
    while (*s1 && *s2)
    {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2))
        {
            return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
        }
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

void format_domain_name(const char *domain, char *output)
{
    int out_pos = 0;
    int label_start = 0;
    for (int i = 0; i <= strlen(domain); i++)
    {
        if (i == strlen(domain) || domain[i] == '.')
        {
            int label_len = i - label_start;
            output[out_pos++] = (char)label_len;
            memcpy(output + out_pos, domain + label_start, label_len);
            out_pos += label_len;
            label_start = i + 1;
        }
    }
    output[out_pos] = 0;
}

int parse_domain_name(unsigned char *buffer, unsigned char *dns_start, char *output)
{
    int out_pos = 0;
    unsigned char *p = buffer;
    int len = 0;
    int jumped = 0;

    while (*p != 0)
    {
        if ((*p & 0xC0) == 0xC0)
        {
            if (!jumped)
            {
                len += 2;
                jumped = 1;
            }
            uint16_t offset = ((*p & 0x3F) << 8) | *(p + 1);
            p = dns_start + offset;
        }
        else
        {
            int label_len = *p++;
            if (!jumped)
            {
                len += (label_len + 1);
            }
            memcpy(output + out_pos, p, label_len);
            out_pos += label_len;
            p += label_len;
            output[out_pos++] = '.';
        }
    }

    if (!jumped)
    {
        len++;
    }

    if (out_pos > 0)
    {
        output[out_pos - 1] = '\0';
    }
    else
    {
        output[0] = '\0';
    }

    return len;
}

char *resolve_dns_recursive(uint16_t tx_id, const char *domain_name, const char *server_ip, int rec_desired, int depth)
{
    // Note: Recursive step also checks cache to catch loops or pre-cached NS records
    char *cached = cache_lookup_exact(domain_name);
    if (cached) {
         // Handle NXDOMAIN signal from cache if necessary, though typical recursion wouldn't 
         // usually hit this unless it's a re-entrant call for the same domain.
        if (strcmp(cached, nxdomain_signal) == 0) {
             printf("Cache hit (NXDOMAIN) for %s\n", domain_name);
             free(cached);
             return nxdomain_signal; 
        }
        printf("Cache hit for %s: %s\n", domain_name, cached);
        return cached;
    }

    if (depth > 10) return NULL;

    int sockfd;
    struct sockaddr_in serv_addr;
    unsigned char buffer[BUFFER_SIZE];

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        return NULL;
    }

    struct timeval timeout;
    timeout.tv_sec = QUERY_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt failed");
        close(sockfd);
        return NULL;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(DNS_PORT);
    serv_addr.sin_addr.s_addr = inet_addr(server_ip);

    memset(buffer, 0, BUFFER_SIZE);
    struct DNSHeader *dns_header = (struct DNSHeader *)buffer;

    dns_header->id = htons(tx_id);
    dns_header->flags = htons(rec_desired ? 0x0100 : 0x0000);
    dns_header->qdcount = htons(1);
    dns_header->ancount = 0;
    dns_header->nscount = 0;
    dns_header->arcount = 0;

    char *qname_ptr = (char *)(buffer + sizeof(struct DNSHeader));

    format_domain_name(domain_name, qname_ptr);
    int qname_len = strlen(qname_ptr) + 1;

    struct DNSQuestionTail *qtail = (struct DNSQuestionTail *)(qname_ptr + qname_len);
    qtail->qtype = htons(1);
    qtail->qclass = htons(1);

    int packet_size = sizeof(struct DNSHeader) + qname_len + sizeof(struct DNSQuestionTail);

    if (sendto(sockfd, buffer, packet_size, 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (errno != EWOULDBLOCK && errno != EAGAIN) perror("sendto failed");
        close(sockfd);
        return NULL;
    }

    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    int n;
    if ((n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&from_addr, &from_len)) < 0)
    {
        if (errno != EWOULDBLOCK && errno != EAGAIN) perror("recvfrom failed");
        close(sockfd);
        return NULL;
    }
    close(sockfd);

    struct DNSHeader *resp_header = (struct DNSHeader *)buffer;
    if (ntohs(resp_header->id) != tx_id) return NULL;

    if ((ntohs(resp_header->flags) & 0x0F) != 0)
    {
        int rcode = (ntohs(resp_header->flags) & 0x0F);
        // fprintf(stderr, "Server %s returned error code %d\n", server_ip, rcode);
        if (rcode == 3) return nxdomain_signal;
        return NULL;
    }

    unsigned char *record_ptr = buffer + packet_size;
    int an_count = ntohs(resp_header->ancount);
    int ns_count = ntohs(resp_header->nscount);
    int ar_count = ntohs(resp_header->arcount);

    for (int i = 0; i < an_count; i++)
    {
        char name_buf[256];
        int name_len = parse_domain_name(record_ptr, buffer, name_buf);
        record_ptr += name_len;

        struct ResourceRecordTail *rr_tail = (struct ResourceRecordTail *)record_ptr;
        record_ptr += sizeof(struct ResourceRecordTail);

        uint16_t type = ntohs(rr_tail->type);
        uint16_t rdlength = ntohs(rr_tail->rdlength);

        if (type == 1 && rdlength == 4)
        {
            struct in_addr ip_addr;
            memcpy(&ip_addr, record_ptr, 4);
            char *resolved_ip = strdup(inet_ntoa(ip_addr));
            printf("Found A record for %s: %s\n", domain_name, resolved_ip);
            return resolved_ip;
        }
        else if (type == 5)
        {
            char cname_buf[256];
            parse_domain_name(record_ptr, buffer, cname_buf);
            printf("Found CNAME record for %s: %s\n", domain_name, cname_buf);
            return resolve_dns(tx_id, cname_buf, rec_desired);
        }
        record_ptr += rdlength;
    }

    char ns_domain[256] = {0};
    for (int i = 0; i < ns_count; i++)
    {
        char name_buf[256];
        int name_len = parse_domain_name(record_ptr, buffer, name_buf);
        record_ptr += name_len;
        struct ResourceRecordTail *rr_tail = (struct ResourceRecordTail *)record_ptr;
        record_ptr += sizeof(struct ResourceRecordTail);
        uint16_t rdlength = ntohs(rr_tail->rdlength);

        if (ntohs(rr_tail->type) == 2 && strlen(ns_domain) == 0)
        {
            parse_domain_name(record_ptr, buffer, ns_domain);
            printf("Found NS referral: %s\n", ns_domain);
        }
        record_ptr += rdlength;
    }

    if (strlen(ns_domain) == 0) return NULL;

    char ns_ip[256] = {0};
    for (int i = 0; i < ar_count; i++)
    {
        char name_buf[256];
        int name_len = parse_domain_name(record_ptr, buffer, name_buf);
        record_ptr += name_len;
        struct ResourceRecordTail *rr_tail = (struct ResourceRecordTail *)record_ptr;
        record_ptr += sizeof(struct ResourceRecordTail);
        uint16_t type = ntohs(rr_tail->type);
        uint16_t rdlength = ntohs(rr_tail->rdlength);

        if (type == 1 && rdlength == 4 && local_strcasecmp(name_buf, ns_domain) == 0)
        {
            struct in_addr ip_addr;
            memcpy(&ip_addr, record_ptr, 4);
            strcpy(ns_ip, inet_ntoa(ip_addr));
            printf("Found glue record for %s: %s\n", ns_domain, ns_ip);
            cache_store(ns_domain, ns_ip);
            break;
        }
        record_ptr += rdlength;
    }

    if (strlen(ns_ip) > 0)
    {
        return resolve_dns_recursive(tx_id, domain_name, ns_ip, rec_desired, depth + 1);
    }
    else
    {
        printf("No glue record for %s. Resolving %s from roots...\n", ns_domain, ns_domain);
        char *new_ns_ip = resolve_dns(tx_id, ns_domain, rec_desired);
        if (new_ns_ip != NULL)
        {
            if (new_ns_ip != nxdomain_signal) cache_store(ns_domain, new_ns_ip);
            char *final_ip = resolve_dns_recursive(tx_id, domain_name, new_ns_ip, rec_desired, depth + 1);
            if (new_ns_ip != nxdomain_signal) free(new_ns_ip);
            return final_ip;
        }
    }

    return NULL;
}

char *resolve_dns(uint16_t tx_id, const char *domain_name, int rec_desired)
{
    char *cached = cache_lookup_exact(domain_name);
    if (cached) {
        printf("Cache exact hit for %s: %s\n", domain_name, cached);
        return cached;
    }


    printf("Starting resolution for %s from root servers...\n", domain_name);
    for (int i = 0; ROOT_NAME_SERVERS[i] != NULL; i++)
    {
        char *result = resolve_dns_recursive(tx_id, domain_name, ROOT_NAME_SERVERS[i], rec_desired, 0);
        if (result != NULL)
        {
            cache_store(domain_name, result);
            return result;
        }
    }

    fprintf(stderr, "Resolution failed for %s\n", domain_name);
    return NULL;
}