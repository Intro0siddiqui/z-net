#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>

#define BUFFER_SIZE 8192

void benchmark(int iterations) {
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    const char *request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";
    size_t request_len = strlen(request);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    int flag = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(1);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        exit(1);
    }

    for (int i = 0; i < iterations; i++) {
        ssize_t total_sent = 0;
        while (total_sent < (ssize_t)request_len) {
            ssize_t n = send(sockfd, request + total_sent, request_len - total_sent, 0);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                perror("send");
                close(sockfd);
                exit(1);
            }
            total_sent += n;
        }

        size_t total_received = 0;
        while (total_received < 1100) {
            ssize_t n = recv(sockfd, buffer, BUFFER_SIZE, 0);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
                break;
            }
            total_received += n;
        }
    }
    close(sockfd);
}

int main(int argc, char *argv[]) {
    int iterations = (argc > 2) ? atoi(argv[2]) : 10000;
    benchmark(iterations);
    return 0;
}
