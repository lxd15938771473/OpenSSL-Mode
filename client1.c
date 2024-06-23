#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    // 初始化 OpenSSL 库
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        printf("SSL_CTX_new 失败\n");
        return EXIT_FAILURE;
    }

    // 创建 TCP 套接字
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        printf("套接字创建失败\n");
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // 与服务器建立连接
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(443); // 假设服务器端口是
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr); // 假设服务器 IP 是 127.0.0.1

    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("连接服务器失败\n");
        close(client_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // 创建 SSL 连接
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_connect(ssl) <= 0) {
        printf("SSL 连接建立失败\n");
        SSL_free(ssl);
        close(client_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // 发送消息到服务器
    char message[1024];
    while (1) {
        printf("请输入要发送的消息（输入 q 退出）：");
        fgets(message, sizeof(message), stdin);
        if (strcmp(message, "q\n") == 0) {
            break;
        }
        SSL_write(ssl, message, strlen(message));

        // 接收服务器消息
        char server_response[1024];
        int bytes_read = SSL_read(ssl, server_response, sizeof(server_response));
        if (bytes_read <= 0) {
            printf("无法从服务器接收消息\n");
            break;
        }
        printf("服务器消息: %s\n", server_response);
    }

    // 关闭连接
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    SSL_CTX_free(ctx);

    return 0;
}

