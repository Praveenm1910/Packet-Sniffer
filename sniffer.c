#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#define MAXCAPTUREBYTES 2048

struct ether_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short type;
};

// Function to print packet details
void print_packet(u_char *count, const struct pcap_pkthdr *h, const u_char *bytes) {
    int i, *counter = (int *)count;

    printf("\n---------------------------------------------\n");
    printf("Packet Count: %d\n", ++(*counter));
    printf("Packet Length: %d bytes\n", h->len);
    printf("Received at: %s", ctime((const time_t *)&h->ts.tv_sec));

    // Parse Ethernet Header
    struct ether_header *eth_header = (struct ether_header *)bytes;
    printf("\n--- Ethernet Header ---\n");
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->src_mac[0], eth_header->src_mac[1], eth_header->src_mac[2],
           eth_header->src_mac[3], eth_header->src_mac[4], eth_header->src_mac[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->dest_mac[0], eth_header->dest_mac[1], eth_header->dest_mac[2],
           eth_header->dest_mac[3], eth_header->dest_mac[4], eth_header->dest_mac[5]);

    // Print Payload
    printf("\n--- Payload ---\n");
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
    printf("\n---------------------------------------------\n");
}

int main(int argc, char *argv[]) {
    char *device = NULL;
    int count = 0;
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *desc;
    char filter_expression[100];
    struct bpf_program fp;
    bpf_u_int32 ip;
    bpf_u_int32 netmask;

    // Check command-line arguments
    if (argc > 1) {
        device = argv[1];
    } else {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Get filter expression from the user
    printf("Enter filter expression (e.g., 'port 7766'): ");
    scanf("%99s", filter_expression);

    // Lookup device information
    if (pcap_lookupnet(device, &ip, &netmask, error) == -1) {
        fprintf(stderr, "Cannot acquire netmask for device %s: %s\n", device, error);
        exit(EXIT_FAILURE);
    }

    printf("Opening device %s for sniffing...\n", device);
    desc = pcap_open_live(device, MAXCAPTUREBYTES, 1, 1000, error);
    if (desc == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device, error);
        exit(EXIT_FAILURE);
    }
    printf("Listening on %s...\n", device);

    // Compile and set filter
    if (pcap_compile(desc, &fp, filter_expression, 0, netmask) == -1) {
        fprintf(stderr, "Cannot parse filter %s: %s\n", filter_expression, pcap_geterr(desc));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(desc, &fp) == -1) {
        fprintf(stderr, "Cannot set filter %s: %s\n", filter_expression, pcap_geterr(desc));
        exit(EXIT_FAILURE);
    }

    // Capture packets
    if (pcap_loop(desc, -1, print_packet, (u_char *)&count) == -1) {
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(desc));
        exit(EXIT_FAILURE);
    }

    pcap_close(desc);
    return 0;
}
