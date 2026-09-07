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
    uint16_t id;      // Transaction ID
    uint16_t flags;   // Flags
    uint16_t qdcount; // Question count
    uint16_t ancount; // Answer count
    uint16_t nscount; // Authority (NS) count
    uint16_t arcount; // Additional (AR) count
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
        // Check for pointer (compression)
        if ((*p & 0xC0) == 0xC0)
        {
            if (!jumped)
            {
                len += 2; // Add 2 bytes for the pointer itself
                jumped = 1;
            }
            // Calculate offset
            uint16_t offset = ((*p & 0x3F) << 8) | *(p + 1);
            p = dns_start + offset; // Jump to new location
        }
        else
        {
            // Not a pointer, it's a label
            int label_len = *p++;
            if (!jumped)
            {
                len += (label_len + 1);
            }
            // Copy label
            memcpy(output + out_pos, p, label_len);
            out_pos += label_len;
            p += label_len;
            // Add a dot
            output[out_pos++] = '.';
        }
    }

    if (!jumped)
    {
        len++; // Account for the final 0 byte
    }

    // Remove trailing dot
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

    // Max recursion depth to prevent loops
    if (depth > 10)
    {
        fprintf(stderr, "Max recursion depth exceeded.\n");
        return NULL;
    }

    printf("Depth %d: Resolving %s using server %s\n", depth, domain_name, server_ip);

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
    dns_header->flags = htons(rec_desired ? 0x0100 : 0x0000); // Standard query, RD=1 or 0
    dns_header->qdcount = htons(1);                           // One question
    dns_header->ancount = 0;
    dns_header->nscount = 0;
    dns_header->arcount = 0;

    char *qname_ptr = (char *)(buffer + sizeof(struct DNSHeader));

    format_domain_name(domain_name, qname_ptr);
    int qname_len = strlen(qname_ptr) + 1; // +1 for the final null byte

    struct DNSQuestionTail *qtail = (struct DNSQuestionTail *)(qname_ptr + qname_len);
    qtail->qtype = htons(1);  // Type A
    qtail->qclass = htons(1); // Class IN

    int packet_size = sizeof(struct DNSHeader) + qname_len + sizeof(struct DNSQuestionTail);

    if (sendto(sockfd, buffer, packet_size, 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (errno == EWOULDBLOCK || errno == EAGAIN)
        {
            fprintf(stderr, "Socket timeout resolving %s at %s\n", domain_name, server_ip);
        }
        else
        {
            perror("sendto failed");
        }
        close(sockfd);
        return NULL;
    }

    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    int n;
    if ((n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&from_addr, &from_len)) < 0)
    {
        if (errno == EWOULDBLOCK || errno == EAGAIN)
        {
            fprintf(stderr, "Socket timeout resolving %s at %s\n", domain_name, server_ip);
        }
        else
        {
            perror("recvfrom failed");
        }
        close(sockfd);
        return NULL;
    }
    close(sockfd);

    struct DNSHeader *resp_header = (struct DNSHeader *)buffer;
    if (ntohs(resp_header->id) != tx_id)
    {
        fprintf(stderr, "Transaction ID mismatch!\n");
        return NULL;
    }

    if ((ntohs(resp_header->flags) & 0x0F) != 0)
    {

        int rcode = (ntohs(resp_header->flags) & 0x0F);
        fprintf(stderr, "Server %s returned error code %d\n", server_ip, rcode);

        if (rcode == 3) { // RCODE 3 is NXDOMAIN
            return nxdomain_signal; 
        }
        
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

        if (type == 1)
        {
            if (rdlength == 4)
            {
                struct in_addr ip_addr;
                memcpy(&ip_addr, record_ptr, 4);
                char *resolved_ip = strdup(inet_ntoa(ip_addr));
                printf("Found A record for %s: %s\n", domain_name, resolved_ip);
                return resolved_ip;
            }
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

    if (strlen(ns_domain) == 0)
    {
        fprintf(stderr, "No A record and no NS referral from %s.\n", server_ip);
        return NULL;
    }

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
            char *final_ip = resolve_dns_recursive(tx_id, domain_name, new_ns_ip, rec_desired, depth + 1);
            free(new_ns_ip); 
            return final_ip; 
        }
        else
        {
            fprintf(stderr, "Failed to resolve nameserver domain %s\n", ns_domain);
            return NULL;
        }
    }

    return NULL; 
}


char *resolve_dns(uint16_t tx_id, const char *domain_name, int rec_desired)
{
    printf("Starting resolution for %s from root servers...\n", domain_name);

    for (int i = 0; ROOT_NAME_SERVERS[i] != NULL; i++)
    {
        char *result = resolve_dns_recursive(tx_id, domain_name, ROOT_NAME_SERVERS[i], rec_desired, 0);

        if (result == nxdomain_signal)
        {
            return nxdomain_signal; 
        }

        if (result != NULL)
        {
            return result; 
        }
    }

    fprintf(stderr, "Resolution failed for %s after trying all root servers.\n", domain_name);
    return NULL;
}

// int main(int argc, char *argv[])
// {
//     if (argc < 2)
//     {
//         fprintf(stderr, "Usage: %s <domain_name>\n", argv[0]);
//         return 1;
//     }

//     const char *domain_to_resolve = argv[1];

//     srand(time(NULL));
//     uint16_t tx_id = rand() & 0xFFFF;

//     printf("--- Resolving %s (TX_ID: %u) (Iterative) ---\n", domain_to_resolve, tx_id);
//     // red desired = 0 -> iterative
//     char *resolved_ip = resolve_dns(tx_id, domain_to_resolve, 0);

//     if (resolved_ip != NULL)
//     {
//         printf("\n=====================================\n");
//         printf("Final Answer for %s: %s\n", domain_to_resolve, resolved_ip);
//     }
//     else
//     {
//         printf("\n=====================================\n");
//         printf("Failed to resolve %s\n", domain_to_resolve);
//         printf("=====================================\n");
//     }

//     return 0;
// }