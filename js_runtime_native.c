#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

void benchmark(int iterations) {
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[4096];
    const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) exit(1);

    int flag = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) exit(1);

    for (int i = 0; i < iterations; i++) {
        if (i % 1000 == 0) printf("Progress: %d/%d\n", i, iterations);
        send(sockfd, request, strlen(request), 0);
        // Expecting 1024 bytes payload + headers
        int received = 0;
        while (received < 1100) { // Approx header + payload
            int n = recv(sockfd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            received += n;
        }
    }

    close(sockfd);
}

int main(int argc, char *argv[]) {
    int iterations = (argc > 2) ? atoi(argv[2]) : 50000;
    benchmark(iterations);
    return 0;
}
