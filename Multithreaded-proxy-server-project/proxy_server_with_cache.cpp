// proxy_server_with_cache.cpp
// Converted from proxy_server_with_cache.c -> C++ source file (Option A)

#include "proxy_parse.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstddef>
#include <ctime>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include <pthread.h>
#include <semaphore.h>

#include <iostream>

#define MAX_BYTES 4096    // max allowed size of request/response
#define MAX_CLIENTS 400     // max number of client requests served at a time
#define MAX_SIZE (200 * (1 << 20))     // size of the cache (bytes)
#define MAX_ELEMENT_SIZE (10 * (1 << 20))     // max size of an element in cache

typedef struct cache_element cache_element;

struct cache_element {
    char* data;         // data stores response
    int len;            // length of data (number of bytes)
    char* url;          // url stores the request (key)
    time_t lru_time_track;    // LRU timestamp
    cache_element* next;    // pointer to next element
};

cache_element* find(char* url);
int add_cache_element(char* data, int size, char* url);
void remove_cache_element();

int port_number = 8080;             // Default Port
int proxy_socketId;                 // socket descriptor of proxy server
pthread_t tid[MAX_CLIENTS];         // array to store the thread ids of clients
sem_t seamaphore;                   // semaphore to limit active clients
pthread_mutex_t lock;               // mutex is used for locking the cache

cache_element* head = nullptr;      // pointer to the head of cache linked list
int cache_size = 0;                 // current cache size in bytes

/* sendErrorMessage: send a simple HTML error response to the client socket */
int sendErrorMessage(int socket, int status_code)
{
    char str[1024];
    char currentTime[50];
    time_t now = time(0);

    struct tm data = *gmtime(&now);
    strftime(currentTime, sizeof(currentTime), "%a, %d %b %Y %H:%M:%S %Z", &data);

    switch (status_code)
    {
        case 400:
            snprintf(str, sizeof(str),
                     "HTTP/1.1 400 Bad Request\r\nContent-Length: 95\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n"
                     "<HTML><HEAD><TITLE>400 Bad Request</TITLE></HEAD>\n<BODY><H1>400 Bad Rqeuest</H1>\n</BODY></HTML>",
                     currentTime);
            printf("400 Bad Request\n");
            send(socket, str, strlen(str), 0);
            break;

        case 403:
            snprintf(str, sizeof(str),
                     "HTTP/1.1 403 Forbidden\r\nContent-Length: 112\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n"
                     "<HTML><HEAD><TITLE>403 Forbidden</TITLE></HEAD>\n<BODY><H1>403 Forbidden</H1><br>Permission Denied\n</BODY></HTML>",
                     currentTime);
            printf("403 Forbidden\n");
            send(socket, str, strlen(str), 0);
            break;

        case 404:
            snprintf(str, sizeof(str),
                     "HTTP/1.1 404 Not Found\r\nContent-Length: 91\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n"
                     "<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\n<BODY><H1>404 Not Found</H1>\n</BODY></HTML>",
                     currentTime);
            printf("404 Not Found\n");
            send(socket, str, strlen(str), 0);
            break;

        case 500:
            snprintf(str, sizeof(str),
                     "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 115\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n"
                     "<HTML><HEAD><TITLE>500 Internal Server Error</TITLE></HEAD>\n<BODY><H1>500 Internal Server Error</H1>\n</BODY></HTML>",
                     currentTime);
            send(socket, str, strlen(str), 0);
            break;

        case 501:
            snprintf(str, sizeof(str),
                     "HTTP/1.1 501 Not Implemented\r\nContent-Length: 103\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n"
                     "<HTML><HEAD><TITLE>404 Not Implemented</TITLE></HEAD>\n<BODY><H1>501 Not Implemented</H1>\n</BODY></HTML>",
                     currentTime);
            printf("501 Not Implemented\n");
            send(socket, str, strlen(str), 0);
            break;

        case 505:
            snprintf(str, sizeof(str),
                     "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 125\r\nConnection: keep-alive\r\nContent-Type: text/html\r\nDate: %s\r\nServer: VaibhavN/14785\r\n\r\n"
                     "<HTML><HEAD><TITLE>505 HTTP Version Not Supported</TITLE></HEAD>\n<BODY><H1>505 HTTP Version Not Supported</H1>\n</BODY></HTML>",
                     currentTime);
            printf("505 HTTP Version Not Supported\n");
            send(socket, str, strlen(str), 0);
            break;

        default:
            return -1;
    }
    return 1;
}

/* connectRemoteServer: connect to remote host, return socket fd or -1 on error
   host_addr is C-style string (const char*) for compatibility */
int connectRemoteServer(const char* host_addr, int port_num)
{
    // Creating Socket for remote server
    int remoteSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (remoteSocket < 0)
    {
        printf("Error in Creating Socket.\n");
        return -1;
    }

    // Get host by the name or ip address provided
    struct hostent *host = gethostbyname(host_addr);
    if (host == nullptr)
    {
        fprintf(stderr, "No such host exists.\n");
        close(remoteSocket);
        return -1;
    }

    struct sockaddr_in server_addr;
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_num);

    bcopy((char *)host->h_addr, (char *)&server_addr.sin_addr.s_addr, host->h_length);

    if (connect(remoteSocket, (struct sockaddr*)&server_addr, (socklen_t)sizeof(server_addr)) < 0)
    {
        fprintf(stderr, "Error in connecting !\n");
        close(remoteSocket);
        return -1;
    }

    return remoteSocket;
}

/* handle_request: forward the parsed GET request to remote server, stream response back,
   gather the response into a temp buffer and add to cache
*/
int handle_request(int clientSocket, ParsedRequest *request, char *tempReq)
{
    if (!request) return -1;

    // Build request line + headers in a C-style buffer to send to remote
    std::string sendbuf;
    sendbuf.reserve(4096);
    sendbuf += "GET ";
    sendbuf += request->path;            // std::string
    sendbuf += " ";
    sendbuf += request->version;
    sendbuf += "\r\n";

    if (ParsedHeader_set(request, "Connection", "close") < 0) {
        printf("set header key not work\n");
    }

    if (ParsedHeader_get(request, "Host") == nullptr) {
        if (ParsedHeader_set(request, "Host", request->host.c_str()) < 0) {
            printf("Set \"Host\" header key not working\n");
        }
    }

    // Prepare a temporary C buffer for headers unparse
    char hdrbuf[MAX_BYTES];
    int hdr_ok = ParsedRequest_unparse_headers(request, hdrbuf, (size_t)MAX_BYTES);
    if (hdr_ok < 0) {
        printf("unparse failed\n");
        // continue anyway
    } else {
        sendbuf += std::string(hdrbuf, ParsedHeader_headersLen(request));
    }

    // default server port
    int server_port = 80;
    if (!request->port.empty()) {
        // convert port string to int safely
        server_port = atoi(request->port.c_str());
    }

    int remoteSocketID = connectRemoteServer(request->host.c_str(), server_port);
    if (remoteSocketID < 0) return -1;

    // send request to remote
    ssize_t bytes_sent = send(remoteSocketID, sendbuf.c_str(), sendbuf.size(), 0);
    if (bytes_sent < 0) {
        perror("Error sending request to remote");
        close(remoteSocketID);
        return -1;
    }

    // read response from remote and stream to client; also accumulate into temp buffer
    char recvbuf[MAX_BYTES];
    ssize_t n = recv(remoteSocketID, recvbuf, MAX_BYTES - 1, 0);
    // accumulate response in a dynamically growing buffer like original
    char* temp_buffer = (char*)malloc(MAX_BYTES);
    if (!temp_buffer) {
        close(remoteSocketID);
        return -1;
    }
    int temp_buffer_size = MAX_BYTES;
    int temp_buffer_index = 0;

    while (n > 0)
    {
        // send to client
        ssize_t sent_to_client = send(clientSocket, recvbuf, n, 0);
        if (sent_to_client < 0) {
            perror("Error in sending data to client socket.");
            break;
        }

        // append to temp_buffer
        if (temp_buffer_index + n >= temp_buffer_size) {
            // expand
            int new_size = temp_buffer_size + MAX_BYTES;
            char* p = (char*)realloc(temp_buffer, new_size);
            if (!p) {
                // allocation failed, free and exit
                free(temp_buffer);
                close(remoteSocketID);
                return -1;
            }
            temp_buffer = p;
            temp_buffer_size = new_size;
        }
        memcpy(temp_buffer + temp_buffer_index, recvbuf, (size_t)n);
        temp_buffer_index += (int)n;

        // read next chunk
        memset(recvbuf, 0, sizeof(recvbuf));
        n = recv(remoteSocketID, recvbuf, MAX_BYTES - 1, 0);
    }

    // Null-terminate for string operations; original used strlen(temp_buffer)
    if (temp_buffer_index >= temp_buffer_size) {
        // ensure space for NUL
        char* p2 = (char*)realloc(temp_buffer, temp_buffer_size + 1);
        if (!p2) { free(temp_buffer); close(remoteSocketID); return -1; }
        temp_buffer = p2;
        temp_buffer_size += 1;
    }
    temp_buffer[temp_buffer_index] = '\0';

    // add to cache (preserving original semantics)
    add_cache_element(temp_buffer, temp_buffer_index, tempReq);

    printf("Done\n");

    // free temporary buffer (add_cache_element makes its own copy)
    free(temp_buffer);

    close(remoteSocketID);
    return 0;
}

/* checkHTTPversion: check if version string is HTTP/1.1 or HTTP/1.0
   adapted to accept const char* */
int checkHTTPversion(const char *msg)
{
    int version = -1;
    if (!msg) return -1;

    if (strncmp(msg, "HTTP/1.1", 8) == 0) {
        version = 1;
    } else if (strncmp(msg, "HTTP/1.0", 8) == 0) {
        version = 1; // treat 1.0 like 1.1 as in original
    } else {
        version = -1;
    }
    return version;
}

/* thread_fn: handle client connection in a thread */
void* thread_fn(void* socketNew)
{
    sem_wait(&seamaphore);
    int p;
    sem_getvalue(&seamaphore, &p);
    printf("semaphore value:%d\n", p);

    int* t = (int*)(socketNew);
    int socket = *t;           // socket descriptor of the connected client
    int bytes_send_client, len;

    char *buffer = (char*)calloc(MAX_BYTES, sizeof(char)); // Creating buffer of 4KB for a client
    if (!buffer) {
        perror("calloc failed");
        sem_post(&seamaphore);
        return NULL;
    }

    memset(buffer, 0, MAX_BYTES);
    bytes_send_client = recv(socket, buffer, MAX_BYTES, 0); // Receiving the Request

    while (bytes_send_client > 0)
    {
        len = (int)strlen(buffer);
        // loop until found "\r\n\r\n"
        if (strstr(buffer, "\r\n\r\n") == nullptr)
        {
            bytes_send_client = recv(socket, buffer + len, MAX_BYTES - len, 0);
        }
        else {
            break;
        }
    }

    // copy the request into tempReq (C-style), used as cache key
    char *tempReq = (char*)malloc(strlen(buffer) + 1);
    if (!tempReq) {
        free(buffer);
        sem_post(&seamaphore);
        return NULL;
    }
    strcpy(tempReq, buffer);

    // check for request in cache
    cache_element* temp = find(tempReq);

    if (temp != nullptr) {
        // request found in cache, send cached response to client
        int size_bytes = temp->len;
        int pos = 0;
        char response[MAX_BYTES];
        while (pos < size_bytes) {
            memset(response, 0, MAX_BYTES);
            int chunk = ((size_bytes - pos) >= MAX_BYTES) ? MAX_BYTES : (size_bytes - pos);
            memcpy(response, temp->data + pos, chunk);
            ssize_t s = send(socket, response, chunk, 0);
            if (s <= 0) break;
            pos += chunk;
        }
        printf("Data retrieved from the Cache\n\n");
        // print last chunk for debug (like original attempted)
        // printf("%s\n\n", response);
        // We do not return here in original; original had commented-out close/sem_post
    }
    else if (bytes_send_client > 0)
    {
        len = (int)strlen(buffer);
        // Parsing the request
        ParsedRequest* request = ParsedRequest_create();

        if (ParsedRequest_parse(request, buffer, len) < 0)
        {
            printf("Parsing failed\n");
        }
        else
        {
            memset(buffer, 0, MAX_BYTES);
            if (request->method == "GET")
            {
                if (!request->host.empty() && !request->path.empty() && (checkHTTPversion(request->version.c_str()) == 1))
                {
                    int rc = handle_request(socket, request, tempReq); // Handle GET request
                    if (rc == -1)
                    {
                        sendErrorMessage(socket, 500);
                    }
                }
                else {
                    sendErrorMessage(socket, 500); // 500 Internal Error
                }
            }
            else {
                printf("This code doesn't support any method other than GET\n");
            }
        }
        ParsedRequest_destroy(request);
    }
    else if (bytes_send_client < 0)
    {
        perror("Error in receiving from client.\n");
    }
    else if (bytes_send_client == 0)
    {
        printf("Client disconnected!\n");
    }

    shutdown(socket, SHUT_RDWR);
    close(socket);
    free(buffer);
    sem_post(&seamaphore);

    sem_getvalue(&seamaphore, &p);
    printf("Semaphore post value:%d\n", p);
    free(tempReq);
    return NULL;
}

/* main: initialize server, accept clients and spawn thread_fn for each connection */
int main(int argc, char * argv[]) {

    int client_socketId, client_len;
    struct sockaddr_in server_addr, client_addr;

    sem_init(&seamaphore, 0, MAX_CLIENTS);
    pthread_mutex_init(&lock, NULL);

    if (argc == 2)
    {
        port_number = atoi(argv[1]);
    }
    else
    {
        printf("Too few arguments\n");
        exit(1);
    }

    printf("Setting Proxy Server Port : %d\n", port_number);

    // creating the proxy socket
    proxy_socketId = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_socketId < 0)
    {
        perror("Failed to create socket.\n");
        exit(1);
    }

    int reuse = 1;
    if (setsockopt(proxy_socketId, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed\n");

    memset((char*)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_number);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(proxy_socketId, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Port is not free\n");
        exit(1);
    }
    printf("Binding on port: %d\n", port_number);

    int listen_status = listen(proxy_socketId, MAX_CLIENTS);
    if (listen_status < 0)
    {
        perror("Error while Listening !\n");
        exit(1);
    }

    int i = 0;
    int Connected_socketId[MAX_CLIENTS];

    while (1)
    {
        memset((char*)&client_addr, 0, sizeof(client_addr));
        client_len = sizeof(client_addr);

        client_socketId = accept(proxy_socketId, (struct sockaddr*)&client_addr, (socklen_t*)&client_len);
        if (client_socketId < 0)
        {
            fprintf(stderr, "Error in Accepting connection !\n");
            exit(1);
        }
        else {
            Connected_socketId[i] = client_socketId;
        }

        struct sockaddr_in* client_pt = (struct sockaddr_in*)&client_addr;
        struct in_addr ip_addr = client_pt->sin_addr;
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN);
        printf("Client is connected with port number: %d and ip address: %s \n", ntohs(client_addr.sin_port), str);

        pthread_create(&tid[i], NULL, thread_fn, (void*)&Connected_socketId[i]);
        i++;
        if (i >= MAX_CLIENTS) i = 0; // wrap index to avoid overflow (original code didn't)
    }

    close(proxy_socketId);
    return 0;
}

/* cache functions (find, remove_cache_element, add_cache_element) kept with original semantics */

/* find: search for url in the cache, update lru_time_track on hit and return pointer */
cache_element* find(char* url) {
    cache_element* site = nullptr;
    int temp_lock_val = pthread_mutex_lock(&lock);
    printf("Remove Cache Lock Acquired %d\n", temp_lock_val);
    if (head != nullptr) {
        site = head;
        while (site != nullptr) {
            if (!strcmp(site->url, url)) {
                printf("LRU Time Track Before : %ld", site->lru_time_track);
                printf("\nurl found\n");
                site->lru_time_track = time(nullptr);
                printf("LRU Time Track After : %ld", site->lru_time_track);
                break;
            }
            site = site->next;
        }
    } else {
        printf("\nurl not found\n");
    }
    temp_lock_val = pthread_mutex_unlock(&lock);
    printf("Remove Cache Lock Unlocked %d\n", temp_lock_val);
    return site;
}

/* remove_cache_element: remove the least-recently-used element from cache */
void remove_cache_element() {
    cache_element *p, *q, *temp;
    int temp_lock_val = pthread_mutex_lock(&lock);
    printf("Remove Cache Lock Acquired %d\n", temp_lock_val);

    if (head != nullptr) {
        p = head;
        q = head;
        temp = head;
        // iterate through list to find minimum lru_time_track
        while (q->next != nullptr) {
            if ((q->next)->lru_time_track < temp->lru_time_track) {
                temp = q->next;
                p = q;
            }
            q = q->next;
        }
        if (temp == head) {
            head = head->next;
        } else {
            p->next = temp->next;
        }
        cache_size = cache_size - (temp->len) - (int)sizeof(cache_element) - (int)strlen(temp->url) - 1;
        free(temp->data);
        free(temp->url);
        free(temp);
    }

    temp_lock_val = pthread_mutex_unlock(&lock);
    printf("Remove Cache Lock Unlocked %d\n", temp_lock_val);
}

/* add_cache_element: add new element to cache, evict LRU elements until enough space */
int add_cache_element(char* data, int size, char* url) {
    int temp_lock_val = pthread_mutex_lock(&lock);
    printf("Add Cache Lock Acquired %d\n", temp_lock_val);
    int element_size = size + 1 + (int)strlen(url) + (int)sizeof(cache_element);
    if (element_size > MAX_ELEMENT_SIZE) {
        temp_lock_val = pthread_mutex_unlock(&lock);
        printf("Add Cache Lock Unlocked %d\n", temp_lock_val);
        return 0;
    } else {
        while (cache_size + element_size > MAX_SIZE) {
            remove_cache_element();
        }
        cache_element* element = (cache_element*) malloc(sizeof(cache_element));
        if (!element) {
            temp_lock_val = pthread_mutex_unlock(&lock);
            printf("Add Cache Lock Unlocked %d\n", temp_lock_val);
            return 0;
        }
        element->data = (char*)malloc(size + 1);
        if (!element->data) {
            free(element);
            temp_lock_val = pthread_mutex_unlock(&lock);
            printf("Add Cache Lock Unlocked %d\n", temp_lock_val);
            return 0;
        }
        memcpy(element->data, data, (size_t)size);
        element->data[size] = '\0';

        element->url = (char*)malloc(1 + (strlen(url) * sizeof(char)));
        if (!element->url) {
            free(element->data);
            free(element);
            temp_lock_val = pthread_mutex_unlock(&lock);
            printf("Add Cache Lock Unlocked %d\n", temp_lock_val);
            return 0;
        }
        strcpy(element->url, url);
        element->lru_time_track = time(nullptr);
        element->next = head;
        element->len = size;
        head = element;
        cache_size += element_size;

        temp_lock_val = pthread_mutex_unlock(&lock);
        printf("Add Cache Lock Unlocked %d\n", temp_lock_val);
        return 1;
    }
    return 0;
}
