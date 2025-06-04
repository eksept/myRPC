#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <json-c/json.h>

#define BUFFER_SIZE 4096

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -c <command> -h <host> -p <port> [-s | -d] [-u <user>]\n", prog);
    fprintf(stderr, "  -c, --command   Command to execute on server\n");
    fprintf(stderr, "  -h, --host      Server IP address\n");
    fprintf(stderr, "  -p, --port      Server port number\n");
    fprintf(stderr, "  -s, --stream    Use TCP\n");
    fprintf(stderr, "  -d, --dgram     Use UDP\n");
    fprintf(stderr, "  -u, --user      Specify username manually\n");
    fprintf(stderr, "      --help      Show this help message\n");
}

int main(int argc, char *argv[]) {
    char *cmd = NULL, *ip = NULL, *user = NULL;
    int port = 0, tcp = 0, udp = 0;

    static struct option opts[] = {
        {"command", required_argument, 0, 'c'},
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"stream", no_argument, 0, 's'},
        {"dgram", no_argument, 0, 'd'},
        {"user", required_argument, 0, 'u'},
        {"help", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int ch, idx;
    while ((ch = getopt_long(argc, argv, "c:h:p:sdu:", opts, &idx)) != -1) {
        switch (ch) {
            case 'c': cmd = strdup(optarg); break;
            case 'h': ip = strdup(optarg); break;
            case 'p': port = atoi(optarg); break;
            case 's': tcp = 1; break;
            case 'd': udp = 1; break;
            case 'u': user = strdup(optarg); break;
            case 0:
                if (strcmp(opts[idx].name, "help") == 0) {
                    usage(argv[0]);
                    return 0;
                }
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (!cmd || !ip || !port || (!tcp && !udp)) {
        usage(argv[0]);
        return 1;
    }

    if (!user) {
        struct passwd *pw = getpwuid(getuid());
        if (!pw) {
            perror("getpwuid");
            return 1;
        }
        user = strdup(pw->pw_name);
    }

    struct json_object *request = json_object_new_object();
    json_object_object_add(request, "login", json_object_new_string(user));
    json_object_object_add(request, "command", json_object_new_string(cmd));
    const char *json_data = json_object_to_json_string(request);

    int sock = socket(AF_INET, (tcp ? SOCK_STREAM : SOCK_DGRAM), 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", ip);
        close(sock);
        return 1;
    }

    char buffer[BUFFER_SIZE] = {0};

    if (tcp) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("connect");
            close(sock);
            return 1;
        }

        send(sock, json_data, strlen(json_data), 0);
        ssize_t len = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (len > 0) {
            buffer[len] = '\0';
            printf("Server reply: %s\n", buffer);
        } else {
            perror("recv");
        }

    } else {
        struct timeval timeout = {.tv_sec = 15, .tv_usec = 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        sendto(sock, json_data, strlen(json_data), 0, (struct sockaddr *)&addr, sizeof(addr));
        socklen_t len = sizeof(addr);
        ssize_t rcv = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&addr, &len);

        if (rcv > 0) {
            buffer[rcv] = '\0';
            printf("Server reply: %s\n", buffer);
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "UDP timeout reached\n");
        } else {
            perror("recvfrom");
        }
    }

    close(sock);
    json_object_put(request);
    free(cmd);
    free(ip);
    free(user);

    return 0;
}
