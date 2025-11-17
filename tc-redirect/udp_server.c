// udp_server.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_PORT 8080      // 监听的端口
#define BUFFER_SIZE 1024      // 缓冲区大小

int main() {
    int sockfd;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in server_addr, client_addr;

    // 创建 UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 配置服务器地址结构
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    server_addr.sin_family = AF_INET;            // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;    // 监听所有本地地址
    server_addr.sin_port = htons(SERVER_PORT);   // 监听端口

    // 绑定 socket 到地址和端口
    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d\n", SERVER_PORT);
    while (1) {
        socklen_t len = sizeof(client_addr); // 客户端地址长度

        // 接收消息
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &len);
        if (n < 0) {
            perror("Receive failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        buffer[n] = '\0'; // 确保消息以 NULL 结尾
        printf("Client: %s\n", buffer);
    }

    close(sockfd);
    return 0;
}

