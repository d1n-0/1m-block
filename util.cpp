#include "util.h"

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
const char* http_request_methods[] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

void usage() {
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.txt\n");
}

unsigned char *get_http_request_header(unsigned char *packet) {
    IpHdr *iphdr = (IpHdr *)packet;
    if (iphdr->protocol != 0x06) return NULL;

    TcpHdr *tcphdr = (TcpHdr *)(packet + (iphdr->ihl << 2));
    if (ntohs(tcphdr->d_port) != 80) return NULL;

    unsigned char *http_header = ((packet + (iphdr->ihl << 2)) + (tcphdr->offset << 2));
    for (int i = 0; i < sizeof(http_request_methods) / sizeof(http_request_methods[0]); i++) {
        if (
            !strncmp(http_request_methods[i], (char *)http_header, strlen(http_request_methods[i])) &&
            http_header[strlen(http_request_methods[i])] == ' '
        ) {
            return http_header;
        }
    }
    return NULL;
}

bool is_malicious_host(char *http_request_header, std::unordered_set<std::string> data) {
    char *line = strtok(http_request_header, "\r\n");
    while (line != NULL) {
        if (!strncasecmp(line, "Host: ", 6)) {
            printf("%s\n", line);
            if (data.find(std::string(line + 6)) != data.end()) {
                return true;
            }
        }
        line = strtok(NULL, "\r\n");
    }
    return false;
}
