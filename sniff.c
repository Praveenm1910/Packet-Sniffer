#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#define MAXCAPTUREBYTES 2048

void print_packet(u_char *count, const struct pcap_pkthdr *h, const u_char *bytes) {
    int i;
    int *counter = (int *)count;

    printf("---------------------------------------------\n");
    printf("Packet Count: %d\n", ++(*counter));
    printf("Received a packet with length: %d bytes\n", h->len);
    printf("Timestamp: %s", ctime((const time_t *)&h->ts.tv_sec));
    printf("Payload:\n");

    for (i = 0; i < h->len; i++) {
        if (isprint(bytes[i])) {
            printf("%c", bytes[i]);
        } else {
            printf(".");
        }
        if ((i + 1) % 32 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *device = NULL;
    int count = 0;
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *desc;
    char filter_expression[] = "port 7766";
    struct bpf_program fp;
    bpf_u_int32 ip, netmask;

    if (argc > 1) {
        device = argv[1];
    } else {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(device, &ip, &netmask, error) == -1) {
        fprintf(stderr, "Error: Cannot acquire netmask for device %s. %s\n", device, error);
        exit(EXIT_FAILURE);
    }

    printf("Opening device %s for sniffing...\n", device);
    desc = pcap_open_live(device, MAXCAPTUREBYTES, 1, 1000, error);
    if (desc == NULL) {
        fprintf(stderr, "Error: %s\n", error);
        exit(EXIT_FAILURE);
    }

    printf("Listening on %s...\n", device);

    if (pcap_compile(desc, &fp, filter_expression, 0, netmask) == -1) {
        fprintf(stderr, "Error: Cannot parse filter '%s'. %s\n", filter_expression, pcap_geterr(desc));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(desc, &fp) == -1) {
        fprintf(stderr, "Error: Cannot set filter '%s'. %s\n", filter_expression, pcap_geterr(desc));
        exit(EXIT_FAILURE);
    }

    if (pcap_loop(desc, -1, print_packet, (u_char *)&count) == -1) {
        fprintf(stderr, "Error: %s\n", pcap_geterr(desc));
        exit(EXIT_FAILURE);
    }

    pcap_close(desc);
    return 0;
}
