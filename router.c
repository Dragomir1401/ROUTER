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
#define ETHERTYPE_IP 0x0800
#define TIME_EXCEEDED 11

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

int binary_search(struct route_table_entry *rtable, uint32_t searched_ip, int left, int right)
{
	int mid = (left + right) / 2;

	while (left <= right)
	{
		if ((searched_ip & rtable[mid].mask) == rtable[mid].prefix)
		{
			return mid;
		}
		else if (ntohl(searched_ip & rtable[mid].mask) > ntohl(rtable[mid].prefix))
		{
			left = mid + 1;
		}
		else
		{
			right = mid - 1;
		}

		mid = (left + right) / 2;
	}

	return -1;
}

struct route_table_entry *LPM(uint32_t daddr, struct route_table_entry *rtable,
							  uint_fast32_t rtable_size)
{
	int pos = binary_search(rtable, daddr, 0, rtable_size - 1);
	return (pos == -1) ? NULL : &rtable[pos];
}

void update_packet(struct route_table_entry **route_entry, struct arp_entry arp_entry, queue q)
{
	// Remove packet from the packet queue
	char *buf = queue_deq(q);

	// Extract ethernet header
	struct ether_header *ethhdr = (struct ether_header *)buf;

	// Extract router MAC
	uint8_t *MAC = malloc(sizeof(MAC_ADDR_SIZE));
	get_interface_mac((*route_entry)->interface, MAC);

	// Update mac address of sender and reciever
	memmove(ethhdr->ether_shost, MAC, MAC_ADDR_SIZE);
	memmove(ethhdr->ether_dhost, arp_entry.mac, MAC_ADDR_SIZE);
}

void search_next_hop(struct route_table_entry *route_entry, struct arp_entry *arp_cache,
					 uint_fast32_t *arp_cache_size, queue q)
{
	for (int arp_cnt = 0; arp_cnt < *arp_cache_size; arp_cnt++)
	{
		if (route_entry->next_hop == arp_cache[arp_cnt].ip)
			update_packet(&route_entry, arp_cache[arp_cnt], q);
	}
}

void check_packet(queue q, struct route_table_entry *rtable, uint_fast32_t *rtable_size,
				  struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size)
{
	// Check to see if the packet queue is empty
	if (queue_empty(q))
	{
		printf("Packet queue is empty.\n");
		return;
	}

	// Extract packet form queue
	char *buf = queue_peek(q);

	// Extract ip header from packet
	struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// Search for the destination ip to see if it already is in the arp cache
	struct route_table_entry *route_entry = LPM(iphdr->daddr, rtable, *rtable_size);

	// Search for the next hop of the first packet in the arp cache
	search_next_hop(route_entry, arp_cache, arp_cache_size, q);
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
	// Extract arp header
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

void update_checksum(struct iphdr *iphdr)
{
	iphdr->ttl--;
	u_int16_t new_checksum = checksum(iphdr, sizeof(struct iphdr));
	iphdr->check = new_checksum;
}

void check_ttl(struct ether_header *ethhdr, struct iphdr *iphdr, char *buf)
{
	// Throw packages with ttl 0 or 1
	if (iphdr->ttl < 2)
	{
		printf("Time limit was reached...Dropping package.\n");

		// Save destination MAC for ICMP
		uint8_t *dest_mac = malloc(sizeof(MAC_ADDR_SIZE));
		memmove(dest_mac, ethhdr, MAC_ADDR_SIZE);

		// Create ICMP header for sending ICMP message
		struct icmphdr icmphdr;
		memset(&icmphdr, 0, sizeof(struct icmphdr));
		icmphdr.code = 0;
		icmphdr.type = TIME_EXCEEDED;
		icmphdr.checksum = 0;
		icmphdr.checksum = checksum((uint16_t *)&icmphdr, sizeof(struct icmphdr));

		// Send ICMP error
		// TO DO ...

		return;
	}

	update_checksum(iphdr);
}

void search_destination(struct iphdr *iphdr, struct route_table_entry *rtable, uint_fast32_t rtable_size)
{
	// Search with LPM in the route table
	struct route_table_entry *LPM_addr = LPM(iphdr, rtable, rtable_size);
}

int handle_ipv4(char *buf, int interface, int len, struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size,
				queue packet_queue, struct route_table_entry *rtable, uint_fast32_t *rtable_size)
{
	printf("Entering IPv4 protocol...\n");

	// Extract ethernet header
	struct ether_header *ethhdr = (struct ether_header *)buf;

	// Extract ip header
	struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// Check for case where the router itself is the destiantion
	if (iphdr->daddr == interface)
	{
		// Respond to ICMP message
		// TO DO...
	}

	// Check for equality in checksums
	if (checksum(iphdr, sizeof(iphdr)) != iphdr->check)
	{
		printf("Checksum test could not be validated.\n");
		return -1;
	}

	check_ttl(ethhdr, iphdr, buf);

	search_destination(iphdr, rtable, *rtable_size);

	return 0;
}

int compare_MAC(uint8_t *addr1, uint8_t *addr2)
{
	uint32_t *a = (uint32_t *)addr1;
	uint32_t *b = (uint32_t *)addr2;

	if ((*a ^ *b) == 0)
	{
		return ((uint16_t *)(a + 2))[0] == ((uint16_t *)(b + 2))[0];
	}

	return 0;
}

int validate_L2(struct ether_header *eth_hdr, uint8_t *broadcast_addr, int interface)
{
	// Get interface MAC
	uint8_t *interface_MAC = malloc(sizeof(MAC_ADDR_SIZE));
	get_interface_mac(interface, interface_MAC);

	// See if the destination MAC is either broadcast address or interface address
	if (!compare_MAC(eth_hdr->ether_dhost, broadcast_addr) &&
		!compare_MAC(eth_hdr->ether_dhost, interface_MAC))
	{
		printf("L2 could not be validated.\n");
		return -1;
	}

	return 0;
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
		DIE(interface < 0, "Problems at recv_from_any_links\n.");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// Handle ARP protocol case
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
		{
			// handle_arp(buf, arp_cache, &arp_cache_size, packet_queue, rtable, &rtable_size);
		}
		else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			// L2 Validation
			if (validate_L2(eth_hdr, broadcast_addr, interface) == -1)
				continue;

			if (handle_ipv4(buf, interface, len, arp_cache, &arp_cache_size, packet_queue, rtable, &rtable_size) == -1)
				continue;
		}
	}

	free_resources(&rtable, &arp_cache, &broadcast_addr);
}
