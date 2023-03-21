#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#define MAX_ENTRIES_RTABLE 100000
#define MAX_ENTRIES_ARP_CACHE 1000
#define MAC_ADDR_SIZE 6
#define ETHERTYPE_ARP 0x0806

void setup(struct route_table_entry **rtable, uint_fast32_t *rtable_size,
		   struct arp_entry **arp_cache, uint_fast32_t *arp_cache_size, uint8_t **broadcast_addr,
		   queue *packet_queue, char *path)
{

	// Alloc a struct for the routes table and store routes
	*rtable = calloc(MAX_ENTRIES_RTABLE, sizeof(struct route_table_entry));
	DIE(*rtable == NULL, "Error at allocating memory for rtable.\n");
	*rtable_size = read_rtable(path, *rtable);
	DIE(rtable_size < 0, "Rtable is empty.\n");

	// Sort table entries using built in quick sort with comparator which compares:
	// -1- masks
	// -2- for the same mask -> prefixes
	qsort(*rtable, *rtable_size, sizeof(struct route_table_entry), compare_rtable_entries);

	// Create ARP cache to store already found addresses to make a more efficient implementation
	*arp_cache = calloc(MAX_ENTRIES_ARP_CACHE, sizeof(struct arp_entry));
	DIE(*arp_cache == NULL, "Error at allocating memory for ARP cache.\n");
	*arp_cache_size = 0;

	// Store the default broadcast address in a buffer
	*broadcast_addr = malloc(MAC_ADDR_SIZE);
	DIE(*broadcast_addr == NULL, "Error at allocating memory for broadcast address.\n");
	hwaddr_aton("FF:FF:FF:FF:FF:FF", *broadcast_addr);

	// Create packet queue
	*packet_queue = queue_create();
}

void free_resources(struct route_table_entry **rtable,
					struct arp_entry **arp_cache, uint8_t **broadcast_addr)
{
	free(*rtable);
	free(*arp_cache);
	free(*broadcast_addr);
}

void add_arp_cache_entry(struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size, struct arp_entry *new_entry)
{
	int cnt = 0;
	while (cnt < *arp_cache_size)
	{
		// If the new entry is in fact no new we dont add it
		if (arp_cache[cnt].ip == new_entry->ip)
		{
			cnt = -1;
			break;
		}
		cnt++;
	}

	if (cnt == -1)
	{
		return;
	}

	// Insert the new entry at the end
	arp_cache[*arp_cache_size++] = *new_entry;
}

void handle_arp_reply(struct arp_header *arp_hdr, struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size,
					  queue packet_queue, struct route_table_entry *rtable, uint_fast32_t *rtable_size)
{
	printf("Handling ARP reply...\n");

	// Update the ARP cache with the new recieved entry
	struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
	DIE(new_entry == NULL, "Error at allocating memory for new ARP cache entry.\n");

	// Fill IP and MAC for the new entry
	new_entry->ip = arp_hdr->spa;
	memmove(new_entry->mac, arp_hdr->sha, MAC_ADDR_SIZE);
	add_arp_cache_entry(arp_cache, arp_cache_size, new_entry);

	// Check if the packet can be sent now
	//...TO DO
}

void handle_arp(char *buf, struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size,
				queue packet_queue, struct route_table_entry *rtable, uint_fast32_t *rtable_size)
{
	printf("Entering ARP protocol...\n");
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// Reply case
	if (arp_hdr->op == htons(2))
	{
		handle_arp_reply(arp_hdr, arp_cache, arp_cache_size,
						 packet_queue, rtable, rtable_size);
	}

	// Request case
	if (arp_hdr->op == htons(1))
	{
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Declare setup variables
	struct route_table_entry *rtable;
	uint_fast32_t rtable_size;
	struct arp_entry *arp_cache;
	uint_fast32_t arp_cache_size;
	uint8_t *broadcast_addr;
	queue packet_queue;

	// Call setup
	setup(&rtable, &rtable_size, &arp_cache, &arp_cache_size, &broadcast_addr, &packet_queue, argv[1]);

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/********* ARP Protocol *********/

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
		{
			handle_arp(buf, arp_cache, &arp_cache_size, packet_queue, rtable, &rtable_size);
		}
	}

	free_resources(&rtable, &arp_cache, &broadcast_addr);
}
