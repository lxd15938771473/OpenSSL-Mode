#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    // 初始化 OpenSSL 库
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());

// 检查会话恢复配置并设置会话缓存模式
SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL);
    if (!ctx) {
        printf("SSL_CTX_new 失败\n");
        return EXIT_FAILURE;
    }
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
            !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
    // 设置失败，处理错误
    // 例如，可以输出错误信息或者清理资源
    printf("不是1.3");
    SSL_CTX_free(ctx);
    return 0;
    // 在这里返回错误码或者执行其他逻辑
    }

    // 加载服务器证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        printf("加载服务器证书失败\n");
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        printf("加载服务器私钥失败\n");
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // 创建 TCP 套接字
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        printf("套接字创建失败\n");
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // 绑定端口
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(443); // 假设使用端口 12345

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("绑定端口失败\n");
        close(server_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // 监听连接
    if (listen(server_socket, 10) == -1) {
        printf("监听失败\n");
        close(server_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    printf("服务器启动，等待连接...\n");

    // 接受客户端连接
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_socket == -1) {
        printf("接受客户端连接失败\n");
        close(server_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // 创建 SSL 连接
    SSL* ssl = SSL_new(ctx);
    SSL_set_num_tickets(ssl, 10);
    int t = SSL_get_num_tickets(ssl);
    printf("tickets的数量为 %d", t);

    const char *ticket_data = "This is a sample session ticket extension data.";
    int ticket_data_len = strlen(ticket_data); // 获取字符串的长度
    // 现在您可以将这些数据传递给 SSL_set_session_ticket_ext 函数
    SSL_set_session_ticket_ext(ssl, (void *)ticket_data, ticket_data_len);

    t = SSL_get_num_tickets(ssl);
    printf("tickets的数量为 %d", t);
    SSL_set_fd(ssl, client_socket);
    if (SSL_accept(ssl) <= 0) {
        printf("SSL 连接建立失败\n");
        SSL_free(ssl);
        close(client_socket);
        close(server_socket);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    printf("客户端连接成功\n");
    int k = SSL_do_handshake(ssl);
    printf("k的值为 %d", k);
    t = SSL_get_num_tickets(ssl);
    printf("tickets的数量为 %d", t);

    // 接收和发送消息
    char buffer[1024];
    while (1) {
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received <= 0) {
            printf("无法接收消息\n");
            break;
        }
        buffer[bytes_received] = '\0';
        printf("收到客户端消息: %s\n", buffer);

        // 处理消息并回复
        if (strcmp(buffer, "q") == 0 || strcmp(buffer, "Q") == 0) {
            break;
        }
        // 回复客户端
        SSL_write(ssl, buffer, strlen(buffer));
	t = SSL_get_num_tickets(ssl);
	printf("tickets的数量为 %d", t);
    }

    // 关闭连接
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    close(server_socket);
    SSL_CTX_free(ctx);

    return 0;
}


