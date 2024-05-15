#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_set>
#include <string>

#include <netinet/in.h>
#include "iphdr.h"
#include "tcphdr.h"

void usage();
unsigned char *get_http_request_header(unsigned char *packet);
bool is_malicious_host(char *http_request_header, std::unordered_set<std::string> data);
