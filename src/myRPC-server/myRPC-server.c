#include "libmysyslog.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <sys/wait.h>

#define CONF_FILE "/home/da/Desktops/Desktop1/myRPC/config/myRPC.conf"
#define USERS_FILE "/home/da/Desktops/Desktop1/myRPC/config/users.conf"
#define BUF_SIZE 4096

static int log_driver = 0;
static int log_format = 0;
static char log_file[256] = "/var/log/myrpc.log";

typedef struct {
    char login[64];
    char command[512];
} RpcRequest;

void load_server_config(int* port, int* use_tcp) {
    FILE* f = fopen(CONF_FILE, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "path = %255s", log_file)) continue;
        if (sscanf(line, "format = %d", &log_format)) continue;
        if (sscanf(line, "driver = %d", &log_driver)) continue;
        if (sscanf(line, "port = %d", port)) continue;
        if (strstr(line, "socket_type") && strstr(line, "dgram")) *use_tcp = 0;
    }
    fclose(f);
}

int is_user_authorized(const char* login) {
    FILE* f = fopen(USERS_FILE, "r");
    if (!f) {
        perror("Failed to open users.conf");
        printf("Tried to open file: %s\n", USERS_FILE);
        return 0;
    }

    char buf[128];
    while (fgets(buf, sizeof(buf), f)) {
        // Удаляем символ новой строки
        buf[strcspn(buf, "\r\n")] = 0;
        if (strcmp(buf, login) == 0) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

char* quote_shell_arg(const char* str) {
    size_t len = strlen(str);
    char* out = malloc(len * 4 + 3);
    if (!out) return NULL;
    char* p = out;
    *p++ = '\'';
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '\'') {
            strcpy(p, "'\\''");
            p += 4;
        } else {
            *p++ = str[i];
        }
    }
    *p++ = '\'';
    *p = '\0';
    return out;
}

char* read_temp_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return strdup("(no output)");
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    char* data = malloc(size + 1);
    fread(data, 1, size, f);
    data[size] = '\0';
    fclose(f);
    return data;
}

char* execute_command(const char* cmd, int* success) {
    char tmp_out[] = "/tmp/rpc_out_XXXXXX";
    char tmp_err[] = "/tmp/rpc_err_XXXXXX";
    int fd_out = mkstemp(tmp_out);
    int fd_err = mkstemp(tmp_err);
    if (fd_out < 0 || fd_err < 0) {
        if (fd_out >= 0) close(fd_out);
        if (fd_err >= 0) close(fd_err);
        *success = 0;
        return strdup("Failed to create temporary files");
    }
    close(fd_out);
    close(fd_err);

    char* quoted = quote_shell_arg(cmd);
    if (!quoted) {
        *success = 0;
        return strdup("Internal error");
    }

    char shell_cmd[1024];
    snprintf(shell_cmd, sizeof(shell_cmd), "sh -c %s > %s 2> %s", quoted, tmp_out, tmp_err);
    free(quoted);

    int status = system(shell_cmd);
    int ok = 0;
    if (status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        ok = 1;
    }
    *success = ok;

    char* result = read_temp_file(ok ? tmp_out : tmp_err);
    unlink(tmp_out);
    unlink(tmp_err);

    return result;
}

int parse_request(const char* input, RpcRequest* req) {
    struct json_object* root = json_tokener_parse(input);
    if (!root) return 0;

    struct json_object *login_obj = NULL, *cmd_obj = NULL;
    if (json_object_object_get_ex(root, "login", &login_obj) &&
        json_object_object_get_ex(root, "command", &cmd_obj)) {
        snprintf(req->login, sizeof(req->login), "%s", json_object_get_string(login_obj));
        snprintf(req->command, sizeof(req->command), "%s", json_object_get_string(cmd_obj));
        json_object_put(root);
        return 1;
    }

    json_object_put(root);
    return 0;
}

void build_response(int success, const char* result, char* out_json, size_t out_size) {
    struct json_object* reply = json_object_new_object();
    json_object_object_add(reply, "code", json_object_new_int(success ? 0 : 1));
    json_object_object_add(reply, "result", json_object_new_string(result));
    snprintf(out_json, out_size, "%s", json_object_to_json_string(reply));
    json_object_put(reply);
}

int main() {
    int port = 8888;
    int use_tcp = 1;
    load_server_config(&port, &use_tcp);

    log_info("myRPC-сервер запущен на порту %d, протокол: %s", port, use_tcp ? "TCP" : "UDP");

    printf("myRPC-server запущен, слушает порт %d\n", port);
    fflush(stdout);

    int sock = socket(AF_INET, use_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (sock < 0) {
        log_error("Ошибка создания сокета: %s", strerror(errno));
        return 1;
    }

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        log_error("Ошибка bind(): %s", strerror(errno));
        return 1;
    }

    if (use_tcp && listen(sock, 5) < 0) {
        log_error("Ошибка listen(): %s", strerror(errno));
        return 1;
    }

    while (1) {
        char buffer[BUF_SIZE] = {0};
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);

        int conn_fd = use_tcp ? accept(sock, (struct sockaddr*)&client_addr, &addrlen) : sock;
        if (conn_fd < 0 && use_tcp) continue;

        ssize_t received = use_tcp ?
            recv(conn_fd, buffer, sizeof(buffer) - 1, 0) :
            recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&client_addr, &addrlen);

        if (received <= 0) {
            if (use_tcp) close(conn_fd);
            continue;
        }

        buffer[received] = '\0';
        log_info("Получено сообщение: %s", buffer);

        RpcRequest req;
        char json_reply[BUF_SIZE];

        if (!parse_request(buffer, &req)) {
            build_response(1, "Invalid JSON format", json_reply, sizeof(json_reply));
        } else if (!is_user_authorized(req.login)) {
            build_response(1, "Unauthorized user", json_reply, sizeof(json_reply));
        } else {
            int ok = 0;
            char* output = execute_command(req.command, &ok);
            build_response(ok ? 0 : 1, output, json_reply, sizeof(json_reply));
            free(output);
        }

        if (use_tcp) {
            send(conn_fd, json_reply, strlen(json_reply), 0);
            close(conn_fd);
        } else {
            sendto(sock, json_reply, strlen(json_reply), 0, (struct sockaddr*)&client_addr, addrlen);
        }
    }

    close(sock);
    return 0;
}
