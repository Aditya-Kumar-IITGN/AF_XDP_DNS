#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "resolver.c"

#define MAX_WORKER_THREADS 10
#define MAX_PENDING_REQUESTS 100

struct ThreadArgs
{
    int sockfd;
    unsigned char request_buffer[BUFFER_SIZE];
    ssize_t request_len;
    struct sockaddr_in client_addr;
    socklen_t client_len;
};

struct WorkQueue
{
    struct ThreadArgs *tasks[MAX_PENDING_REQUESTS];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond_not_empty;
    pthread_cond_t cond_not_full;
};

struct WorkQueue work_queue;

void work_queue_init(struct WorkQueue *q)
{
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_not_empty, NULL);
    pthread_cond_init(&q->cond_not_full, NULL);
}

void work_queue_push(struct WorkQueue *q, struct ThreadArgs *task)
{
    pthread_mutex_lock(&q->mutex);

    while (q->count >= MAX_PENDING_REQUESTS)
    {
        // printf("Work queue is full, waiting...\n");
        pthread_cond_wait(&q->cond_not_full, &q->mutex);
    }

    q->tasks[q->tail] = task;
    q->tail = (q->tail + 1) % MAX_PENDING_REQUESTS;
    q->count++;

    pthread_cond_signal(&q->cond_not_empty);
    pthread_mutex_unlock(&q->mutex);
}

struct ThreadArgs *work_queue_pop(struct WorkQueue *q)
{
    pthread_mutex_lock(&q->mutex);

    while (q->count == 0)
    {
        pthread_cond_wait(&q->cond_not_empty, &q->mutex);
    }

    struct ThreadArgs *task = q->tasks[q->head];
    q->head = (q->head + 1) % MAX_PENDING_REQUESTS;
    q->count--;

    pthread_cond_signal(&q->cond_not_full);
    pthread_mutex_unlock(&q->mutex);

    return task;
}

void *handle_request(void *arg)
{
    struct ThreadArgs *args = (struct ThreadArgs *)arg;

    unsigned char response_buffer[BUFFER_SIZE];
    memset(response_buffer, 0, BUFFER_SIZE);

    // printf("\n--- [Worker %lu] Received Query from %s:%d ---\n",
        //    pthread_self(), inet_ntoa(args->client_addr.sin_addr), ntohs(args->client_addr.sin_port));

    struct DNSHeader *req_header = (struct DNSHeader *)args->request_buffer;
    unsigned char *qname_ptr = args->request_buffer + sizeof(struct DNSHeader);

    char domain_name[256];
    int qname_len = parse_domain_name(qname_ptr, args->request_buffer, domain_name);

    struct DNSQuestionTail *qtail = (struct DNSQuestionTail *)(qname_ptr + qname_len);
    int question_section_len = qname_len + sizeof(struct DNSQuestionTail);

    uint16_t client_tx_id = ntohs(req_header->id);
    uint16_t client_flags = ntohs(req_header->flags);
    // int rec_desired = (client_flags & 0x0100) ? 1 : 0;
    int rec_desired = 0;

    if (ntohs(req_header->qdcount) != 1 || (client_flags & 0x8000))
    {
        // fprintf(stderr, "[Worker %lu] Ignoring non-standard query.\n", pthread_self());
        free(args);
        return NULL;
    }

    // printf("[Worker %lu] Resolving: %s (Type: %u, Class: %u)\n",
        //    pthread_self(), domain_name, ntohs(qtail->qtype), ntohs(qtail->qclass));

    uint16_t server_tx_id = rand() & 0xFFFF;
    char *resolved_ip = resolve_dns(server_tx_id, domain_name, rec_desired);

    struct DNSHeader *resp_header = (struct DNSHeader *)response_buffer;
    unsigned char *resp_ptr = response_buffer + sizeof(struct DNSHeader);

    memcpy(resp_ptr, qname_ptr, question_section_len);
    resp_ptr += question_section_len;

    resp_header->id = htons(client_tx_id);
    uint16_t resp_flags = 0x8000;
    resp_flags |= (client_flags & 0x0100);
    resp_flags |= 0x0080;

    resp_header->qdcount = htons(1);

    if (resolved_ip == nxdomain_signal)
    {
        // printf("[Worker %lu] Resolution failed (NXDOMAIN)\n", pthread_self());
        resp_flags |= 0x0003;
        resp_header->ancount = htons(0);
    }
    else if (resolved_ip != NULL)
    {
        // printf("[Worker %lu] Resolution success: %s\n", pthread_self(), resolved_ip);
        resp_flags |= 0x0000;
        resp_header->ancount = htons(1);

        *resp_ptr++ = 0xC0;
        *resp_ptr++ = 0x0C;

        struct ResourceRecordTail *rr_tail = (struct ResourceRecordTail *)resp_ptr;
        rr_tail->type = htons(1);
        rr_tail->class = htons(1);
        rr_tail->ttl = htonl(60);
        rr_tail->rdlength = htons(4);
        resp_ptr += sizeof(struct ResourceRecordTail);

        inet_pton(AF_INET, resolved_ip, resp_ptr);
        resp_ptr += 4;

        free(resolved_ip);
    }
    else
    {
        // printf("[Worker %lu] Resolution failed (SERVFAIL)\n", pthread_self());
        resp_flags |= 0x0002;
        resp_header->ancount = htons(0);
    }

    resp_header->flags = htons(resp_flags);
    resp_header->nscount = 0;
    resp_header->arcount = 0;

    int response_size = resp_ptr - response_buffer;

    sendto(args->sockfd, response_buffer, response_size, 0,
           (const struct sockaddr *)&args->client_addr, args->client_len);

    free(args);
    return NULL;
}

void *worker_thread_function(void *arg)
{
    struct WorkQueue *q = (struct WorkQueue *)arg;
    // printf("Worker thread %lu started...\n", pthread_self());

    while (1)
    {

        struct ThreadArgs *task = work_queue_pop(q);

        if (task != NULL)
        {

            handle_request(task);
        }
    }
    return NULL;
}

int main(void)
{
    int sockfd;
    struct sockaddr_in serv_addr;
    srand(time(NULL));

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(DNS_PORT);

    if (bind(sockfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind failed");
        // fprintf(stderr, "Error: Failed to bind to port 53. Are you running as root (or with sudo)?\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    work_queue_init(&work_queue);
    pthread_t worker_threads[MAX_WORKER_THREADS];

    for (int i = 0; i < MAX_WORKER_THREADS; i++)
    {
        if (pthread_create(&worker_threads[i], NULL, worker_thread_function, (void *)&work_queue) != 0)
        {
            perror("pthread_create for worker failed");
            exit(EXIT_FAILURE);
        }
    }

    // printf("DNS server listening on port %d with %d worker threads...\n", DNS_PORT, MAX_WORKER_THREADS);

    while (1)
    {
        struct ThreadArgs *args = malloc(sizeof(struct ThreadArgs));
        if (args == NULL)
        {
            perror("malloc failed");
            continue;
        }

        args->sockfd = sockfd;
        args->client_len = sizeof(args->client_addr);

        ssize_t n = recvfrom(sockfd, args->request_buffer, BUFFER_SIZE, 0,
                             (struct sockaddr *)&args->client_addr, &args->client_len);
        if (n < 0)
        {
            perror("recvfrom failed");
            free(args);
            continue;
        }
        args->request_len = n;

        work_queue_push(&work_queue, args);
    }

    for (int i = 0; i < MAX_WORKER_THREADS; i++)
    {
        pthread_join(worker_threads[i], NULL);
    }

    close(sockfd);
    return 0;
}