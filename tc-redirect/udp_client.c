// udp_client.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_PORT 8080      // 服务器端口
#define SERVER_IP   "127.0.0.1" // 服务器 IP 地址

int main() {
    int sockfd;
    struct sockaddr_in server_addr;

    // 创建 UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 配置服务器地址结构
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;                      // IPv4
    server_addr.sin_port = htons(SERVER_PORT);             // 目标端口
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);    // 目标 IP 地址

    while (1) {
        // 向服务器发送消息
        const char *message = "RTPS, Hello from client";
        sendto(sockfd, message, strlen(message), 0, (const struct sockaddr *)&server_addr, sizeof(server_addr));
        printf("Message sent to server: %s\n", message);
        sleep(1);
    }
    close(sockfd);
    return 0;
}

