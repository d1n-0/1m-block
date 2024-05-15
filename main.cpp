#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <string>
#include <fstream>
#include <unordered_set>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "util.h"

#define TEST
#ifdef TEST
#include <chrono>
#endif

std::unordered_set<std::string> malicious_hosts;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	uint32_t id = 0;
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) id = ntohl(ph->packet_id);
	unsigned char *packet;
	
	if (nfq_get_payload(nfa, &packet) < 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	unsigned char *http_request_header = get_http_request_header(packet);
	if (http_request_header == NULL) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
#ifdef TEST
    std::chrono::steady_clock::time_point begin, end;
    long long int duration;
    begin = std::chrono::steady_clock::now();
#endif
	if (is_malicious_host((char *)http_request_header, malicious_hosts)) {
#ifdef TEST
        end = std::chrono::steady_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin).count();
        printf("%lf[s] for searching host\n", duration / 1000000.0);
#endif
		printf("Malicious host detected\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
#ifdef TEST
    end = std::chrono::steady_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin).count();
    printf("%lf[s] for searching host\n", duration / 1000000.0);
#endif
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

    if (argc < 2) {
        usage();
        return -1;
    }

	std::ifstream file(argv[1]);
	if (!file.is_open()) {
		printf("File open error\n");
		return -1;
	}

#ifdef TEST
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
#endif

	std::string line;
	while (std::getline(file, line)) {
		line = line.substr(line.find(",") + 1);
		if (line.empty()) continue;
		malicious_hosts.insert(line);
	}

#ifdef TEST
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    long long int duration = std::chrono::duration_cast<std::chrono::microseconds> (end - begin).count();
    printf("%lf[s] for loading data\n", duration / 1000000.0);
#endif

	file.close();

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
