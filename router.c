#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#define MAX_ENTRIES_RTABLE 100000
#define MAX_ENTRIES_ARP_CACHE 1000
#define MAC_ADDR_SIZE 6
#define IP_ADDR_SIZE 4
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800
#define TIME_EXCEEDED 11
#define DEST_UNREACH 3
#define ECHO_REPLY 0
#define ARP_REPLY 2
#define ARP_REQUEST 1
#define ICMP_OVER 64
#define ICMP_ECHO 8
#define ERROR -1
#define ECHO 0

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
	hwaddr_aton("ff:ff:ff:ff:ff:ff", *broadcast_addr);

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

char *mac_to_str(uint8_t mac[6])
{
	static char str[18];
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return str;
}

void add_arp_cache_entry(struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size, struct arp_entry *new_entry)
{
	int cnt = 0;
	while (cnt < *arp_cache_size)
	{
		// If the new entry is in fact not new we dont add it
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

	struct in_addr ip_addr;
	ip_addr.s_addr = new_entry->ip;
	printf("Adding entry in arp cache: ip: %s mac: %s.\n\n", inet_ntoa(ip_addr), mac_to_str(new_entry->mac));

	// Insert the new entry at the end
	arp_cache[(*arp_cache_size)] = *new_entry;
	(*arp_cache_size)++;
}

int binary_search(struct route_table_entry *rtable, uint32_t searched_ip, int left, int right)
{
	int mid = (left + right) / 2;

	while (left <= right)
	{
		if ((searched_ip & rtable[mid].mask) == (rtable[mid].prefix & rtable[mid].mask))
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
	uint8_t *MAC = malloc(MAC_ADDR_SIZE);
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

void pop_from_queue(queue packet_queue, struct arp_entry *arp_cache, uint_fast32_t arp_cache_size,
					struct route_table_entry *rtable, uint_fast32_t rtable_size, int len)
{
	if (queue_empty(packet_queue))
	{
		return;
	}

	// Extract packet and headers
	char *buf = (char *)queue_deq(packet_queue);
	struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// Search entry in route table
	struct route_table_entry *entry = LPM(iphdr->daddr, rtable, rtable_size);
	struct in_addr ip_addr;
	printf("Found route for packet dequeued:\n");
	ip_addr.s_addr = iphdr->saddr;
	printf("Source   --- %s.\n", inet_ntoa(ip_addr));
	ip_addr.s_addr = entry->next_hop;
	printf("Next hop --- %s from the route table.\n\n", inet_ntoa(ip_addr));

	for (int cnt = 0; cnt < arp_cache_size; cnt++)
	{
		if (entry->next_hop == arp_cache[cnt].ip)
		{

			struct ether_header *ethhdr = (struct ether_header *)buf;

			// Extract new MAC
			uint8_t *MAC = malloc(MAC_ADDR_SIZE);
			get_interface_mac(entry->interface, MAC);

			// Change source MAC and destination MAC
			memmove(ethhdr->ether_shost, MAC, MAC_ADDR_SIZE);
			memmove(ethhdr->ether_dhost, arp_cache[cnt].mac, MAC_ADDR_SIZE);

			struct in_addr ip_addr;
			ip_addr.s_addr = iphdr->saddr;
			printf("Sending packet from queue...\n");
			printf("Source 	    --- %s .\n", inet_ntoa(ip_addr));
			printf("MAC source  --- %s\n", mac_to_str(ethhdr->ether_shost));
			ip_addr.s_addr = entry->next_hop;
			printf("Destination --- %s.\n", inet_ntoa(ip_addr));
			printf("MAC destin  --- %s\n", mac_to_str(ethhdr->ether_dhost));
			printf("Via interface %d.\n\n", entry->interface);

			// Send packet to next hop
			send_to_link(entry->interface, buf, len);
			return;
		}
	}

	// Reenque packet and print error
	queue_enq(packet_queue, buf);
	printf("Could not find next hop for the first packet in queue.\n");
}

void handle_arp_reply(struct arp_header *arp_hdr, struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size,
					  queue packet_queue, struct route_table_entry *rtable, uint_fast32_t *rtable_size, int len)
{
	printf("Handling ARP reply...\n");
	struct in_addr ip_addr;
	ip_addr.s_addr = arp_hdr->spa;
	printf("Source   -- %s.\n", inet_ntoa(ip_addr));
	ip_addr.s_addr = arp_hdr->tpa;
	printf("Next hop -- %s. from the route table.\n\n", inet_ntoa(ip_addr));

	// Update the ARP cache with the new recieved entry
	struct arp_entry *new_entry = malloc(sizeof(struct arp_entry));
	DIE(new_entry == NULL, "Error at allocating memory for new ARP cache entry.\n");

	// Fill IP and MAC for the new entry
	new_entry->ip = arp_hdr->spa;
	memmove(new_entry->mac, arp_hdr->sha, MAC_ADDR_SIZE);
	add_arp_cache_entry(arp_cache, arp_cache_size, new_entry);

	// Check if the packet can be sent now
	pop_from_queue(packet_queue, arp_cache, *arp_cache_size, rtable, *rtable_size, len);
}

void arp_reply(char *buf, uint8_t *dest_mac, uint8_t *source_mac, uint32_t ip_daddr, uint32_t ip_saddr,
			   int interface, int len)
{
	memset(buf, 0, 1600);

	// Prepare ethernet header
	struct ether_header *ethhdr = (struct ether_header *)(buf);
	ethhdr->ether_type = htons(ETHERTYPE_ARP);
	memcpy(ethhdr->ether_shost, source_mac, MAC_ADDR_SIZE);
	memcpy(ethhdr->ether_dhost, dest_mac, MAC_ADDR_SIZE);

	// Prepare ARP header
	struct arp_header *arphdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	arphdr->op = htons(ARP_REPLY);
	arphdr->ptype = htons(2048);
	arphdr->plen = 4;
	arphdr->htype = htons(1);
	arphdr->hlen = 6;
	memmove(arphdr->sha, source_mac, MAC_ADDR_SIZE);
	memmove(arphdr->tha, dest_mac, MAC_ADDR_SIZE);
	arphdr->spa = ip_saddr;
	arphdr->tpa = ip_daddr;

	// Send packet
	struct in_addr ip_addr;
	ip_addr.s_addr = ip_saddr;
	printf("Sending packet...\n");
	printf("Source      --- %s.\n", inet_ntoa(ip_addr));
	ip_addr.s_addr = ip_daddr;
	printf("Destination --- %s.\n\n", inet_ntoa(ip_addr));
	send_to_link(interface, buf, len);
}

void arp_request(struct route_table_entry *LPM_router)
{

	// Create new ARP Packet
	char *buf = malloc(1600);
	int interface = LPM_router->interface;
	int len = sizeof(struct arp_header) + sizeof(struct ether_header);
	memset(buf, 0, 1600);

	// Alloc the broadcast address
	uint8_t *broadcast_addr = malloc(MAC_ADDR_SIZE);
	hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_addr);

	// Create ethernet header for the packet
	struct ether_header *ethhdr = (struct ether_header *)buf;
	ethhdr->ether_type = ntohs(ETHERTYPE_ARP);
	get_interface_mac(LPM_router->interface, ethhdr->ether_shost);
	memcpy(ethhdr->ether_dhost, broadcast_addr, MAC_ADDR_SIZE);

	// Create the ARP header for the apcket
	struct arp_header *arphdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	arphdr->op = htons(ARP_REQUEST);
	arphdr->ptype = htons(2048); /* aka 0x0800 */
	arphdr->plen = 4;
	arphdr->htype = htons(1); /* Ethernet */
	arphdr->hlen = MAC_ADDR_SIZE;

	get_interface_mac(LPM_router->interface, arphdr->sha);
	arphdr->spa = inet_addr(get_interface_ip(LPM_router->interface));
	arphdr->tpa = LPM_router->next_hop;
	// Send to broadcast address for the request
	memcpy(arphdr->tha, broadcast_addr, MAC_ADDR_SIZE);

	// Print with correct layout
	struct in_addr ip_addr;
	ip_addr.s_addr = arphdr->spa;
	printf("Sending ARP request...\n");
	printf("Source   -- %s.\n\n", inet_ntoa(ip_addr));

	send_to_link(interface, buf, len);
}

void handle_arp(char *buf, struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size,
				queue packet_queue, struct route_table_entry *rtable, uint_fast32_t *rtable_size,
				int len, int interface)
{
	printf("Entering ARP protocol...\n");
	// Extract arp header
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// Reply case -> add the response to the arp cache
	if (arp_hdr->op == htons(2))
	{
		handle_arp_reply(arp_hdr, arp_cache, arp_cache_size,
						 packet_queue, rtable, rtable_size, len);
	}

	// Request case -> reply with the local interface MAC
	if (arp_hdr->op == htons(1))
	{
		uint8_t *recieved_mac = malloc(MAC_ADDR_SIZE);
		get_interface_mac(interface, recieved_mac);

		arp_reply(buf, arp_hdr->sha, recieved_mac, arp_hdr->spa, arp_hdr->tpa, interface, len);
	}
}

void update_checksum(struct iphdr *iphdr)
{
	// Decrement the TTL
	iphdr->ttl--;

	// Update the checksum
	iphdr->check = 0;
	u_int16_t *buf = (u_int16_t *)iphdr;
	int length = sizeof(struct iphdr) >> 1;
	u_int32_t sum = 0;

	while (length--)
	{
		sum += *buf++;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	iphdr->check = (u_int16_t)(~sum);
}

void send_icmp_message(char *buf, int interface, struct iphdr *iphdr, struct ether_header *ethhdr,
					   struct icmphdr *icmphdr, uint8_t *dest_mac, int error_or_echo)
{
	// Make a copy of the original packet
	char *copy = malloc(strlen(buf));
	memmove(copy, buf, strlen(buf));

	// Extract a copy of the headers
	struct ether_header *ethhdr_copy = (struct ether_header *)copy;
	struct iphdr *iphdr_copy = (struct iphdr *)(copy + sizeof(struct ether_header));
	struct icmphdr *icmphdr_copy = (struct icmphdr *)(copy + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Update mac of source and destination at ethernet level
	memmove(ethhdr_copy->ether_dhost, ethhdr->ether_shost, MAC_ADDR_SIZE);
	memmove(ethhdr_copy->ether_shost, dest_mac, MAC_ADDR_SIZE);

	// Update ip addresses of sender and destination at network level and update ip protocol and size
	iphdr_copy->daddr = iphdr->saddr;
	iphdr_copy->saddr = inet_addr(get_interface_ip(interface));
	iphdr_copy->protocol = IPPROTO_ICMP;
	iphdr_copy->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	if (error_or_echo == -1)
	// Error case
	{
		printf("Sending ICMP error from %d to %d.\n", iphdr->saddr, iphdr->daddr);

		// Put 64 more bytes over the IP header
		char *over_ip = malloc(ICMP_OVER);
		memmove(over_ip, buf + sizeof(struct ether_header) + sizeof(struct iphdr), ICMP_OVER);

		// Update ICMP header and add the additional 64 bytes
		memmove(icmphdr_copy, icmphdr, sizeof(struct icmphdr));
		memmove(copy + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), over_ip, ICMP_OVER);

		// Send the copy created in this function
		send_to_link(interface, copy, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_OVER);

		return;
	}
	else if (!error_or_echo)
	// Message case
	{
		printf("Sending ICMP echo from %d to %d.\n", iphdr->saddr, iphdr->daddr);

		/* Update ICMP Header */
		memmove(icmphdr_copy, icmphdr, sizeof(struct icmphdr));

		// Send the copy created in this function
		send_to_link(interface, copy, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	}
}

int check_ttl(struct ether_header *ethhdr, struct iphdr *iphdr, char *buf, int interface)
{
	// Throw packages with ttl 0 or 1
	if (iphdr->ttl < 2)
	{
		printf("Time limit was reached...Dropping package.\n");

		// Save destination MAC for ICMP
		uint8_t *dest_mac = malloc(MAC_ADDR_SIZE);
		memmove(dest_mac, ethhdr->ether_dhost, MAC_ADDR_SIZE);

		// Create ICMP header for sending ICMP message
		struct icmphdr icmphdr;
		memset(&icmphdr, 0, sizeof(struct icmphdr));
		icmphdr.code = 0;
		icmphdr.type = TIME_EXCEEDED;
		icmphdr.checksum = 0;
		icmphdr.checksum = checksum((uint16_t *)&icmphdr, sizeof(struct icmphdr));

		// Send ICMP error
		send_icmp_message(buf, interface, iphdr, ethhdr, &icmphdr, dest_mac, ERROR);

		return -1;
	}

	update_checksum(iphdr);
	return 0;
}

int search_ip_arp_cache(struct arp_entry *arp_table, int arp_table_len, uint32_t searched_ip, uint8_t *mac_targeted)
{
	for (int i = 0; i < arp_table_len; i++)
	{
		if (arp_table[i].ip == searched_ip)
		{
			memmove(mac_targeted, &arp_table[i].mac, MAC_ADDR_SIZE);
			return 0;
		}
	}
	return -1;
}

int search_destination(struct iphdr *iphdr, struct ether_header *ethhdr, struct route_table_entry *rtable,
					   uint_fast32_t rtable_size, int interface, char *buf, struct arp_entry *arp_cache,
					   uint_fast32_t arp_cache_size, int len, queue packet_queue)
{
	// Search with LPM in the route table
	struct route_table_entry *LPM_addr = LPM(iphdr->daddr, rtable, rtable_size);

	if (LPM_addr == NULL)
	{
		// Print with correct layout
		struct in_addr ip_addr;
		ip_addr.s_addr = iphdr->saddr;
		printf("Source   -- %s.\n", inet_ntoa(ip_addr));
		printf("Next hop -- [Destination unreachable] from the route table.\n\n");

		// Save destination MAC for ICMP
		uint8_t *dest_mac = malloc(sizeof(MAC_ADDR_SIZE));
		memmove(dest_mac, ethhdr->ether_dhost, MAC_ADDR_SIZE);

		// Create new ICMP Header for error
		struct icmphdr icmphdr;
		memset(&icmphdr, 0, sizeof(struct icmphdr));
		icmphdr.code = 0;
		icmphdr.type = DEST_UNREACH;
		icmphdr.checksum = 0;
		icmphdr.checksum = checksum((uint16_t *)&icmphdr, sizeof(struct icmphdr));

		// Send icmp error
		send_icmp_message(buf, interface, iphdr, ethhdr, &icmphdr, dest_mac, ERROR);
		return -1;
	}

	// Print with correct layout
	struct in_addr ip_addr;
	ip_addr.s_addr = iphdr->saddr;
	printf("Found route for:\n");
	printf("Source   -- %s.\n", inet_ntoa(ip_addr));
	ip_addr.s_addr = LPM_addr->next_hop;
	printf("Next hop -- %s from the route table.\n\n", inet_ntoa(ip_addr));

	// Find next mac to send the packet to
	uint8_t *next_mac = malloc(MAC_ADDR_SIZE);
	// 0 for succes, -1 for error
	int res = search_ip_arp_cache(arp_cache, arp_cache_size, LPM_addr->next_hop, next_mac);

	if (!res)
	{
		// Print correct layout
		printf("Found destination MAC: %s in the arp cache.\n\n", mac_to_str(next_mac));

		// Change MAC destination
		get_interface_mac(LPM_addr->interface, ethhdr->ether_shost);
		memcpy(ethhdr->ether_dhost, next_mac, MAC_ADDR_SIZE);

		struct in_addr ip_addr;
		ip_addr.s_addr = iphdr->saddr;
		printf("Sending packet...\n");
		printf("Source      --- %s.\n", inet_ntoa(ip_addr));
		ip_addr.s_addr = iphdr->daddr;
		printf("Destination --- %s.\n", inet_ntoa(ip_addr));
		printf("Interface: %d\n\n", LPM_addr->interface);
		// Send to the found in arp cache address
		send_to_link(LPM_addr->interface, buf, len);

		// Exit
		return -1;
	}

	// If we dont find next MAC in arp cache then make an ARP request to find it
	ip_addr.s_addr = iphdr->saddr;
	printf("Enqueuing package...\n");
	printf("Source      --- %s.\n", inet_ntoa(ip_addr));
	ip_addr.s_addr = iphdr->daddr;
	printf("Destination --- %s.\n", inet_ntoa(ip_addr));
	printf("Interface: %d\n\n", interface);
	queue_enq(packet_queue, buf);

	// Make an ARP request
	arp_request(LPM_addr);

	// Exit
	return -1;
}

void icmp_echo(struct iphdr *iphdr, struct ether_header *ethhdr, struct icmphdr *icmphdr,
			   int interface, char *buf)
{
	// Save destination MAC for ICMP
	uint8_t *dest_mac = malloc(MAC_ADDR_SIZE);
	memmove(dest_mac, ethhdr->ether_dhost, MAC_ADDR_SIZE);

	// Create new ICMP Header for error
	struct icmphdr new_icmphdr;
	memset(&icmphdr, 0, sizeof(struct icmphdr));
	new_icmphdr.code = 0;
	new_icmphdr.type = ECHO_REPLY;
	new_icmphdr.checksum = 0;
	new_icmphdr.checksum = checksum((uint16_t *)&icmphdr, sizeof(struct icmphdr));

	// Send icmp echo
	send_icmp_message(buf, interface, iphdr, ethhdr, &new_icmphdr, dest_mac, ECHO);
}

int handle_ipv4(char *buf, int interface, int len, struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size,
				queue packet_queue, struct route_table_entry *rtable, uint_fast32_t *rtable_size)
{
	printf("Entering IPv4 protocol...\n");

	// Extract ethernet header
	struct ether_header *ethhdr = (struct ether_header *)buf;

	// Extract ip header
	struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	struct in_addr ip_addr;
	ip_addr.s_addr = iphdr->saddr;
	printf("Recieved IPv4 package...\n");
	printf("Source      --- %s.\n", inet_ntoa(ip_addr));
	ip_addr.s_addr = iphdr->daddr;
	printf("Destination --- %s.\n", inet_ntoa(ip_addr));
	printf("Interface: %d\n\n", interface);

	// Check for case where the router itself is the destination
	if (iphdr->daddr == inet_addr(get_interface_ip(interface)))
	{
		// Extract ICMP header
		struct icmphdr *icmphdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

		// Respond to ICMP message
		if (icmphdr->type == ICMP_ECHO && !icmphdr->code)
			icmp_echo(iphdr, ethhdr, icmphdr, interface, buf);
		return -1;
	}

	// Verify the checksum
	if (checksum((void *)iphdr, sizeof(struct iphdr)))
	{
		printf("Checksum test could not be validated.\n");
		return -1;
	}

	// Check to see if ttl dropped below 2
	if (check_ttl(ethhdr, iphdr, buf, interface) == -1)
	{
		return -1;
	}

	// Search to see if router has address in route table
	if (search_destination(iphdr, ethhdr, rtable, *rtable_size, interface,
						   buf, arp_cache, *arp_cache_size, len, packet_queue) == -1)
	{
		return -1;
	}

	return 0;
}
int compare_MAC(uint8_t *addr1, uint8_t *addr2)
{
	for (int i = 0; i < MAC_ADDR_SIZE; i++)
	{
		if (addr1[i] != addr2[i])
		{
			// They are not equal
			return -1;
		}
	}

	// They are equal
	return 0;
}

int validate_L2(struct ether_header *eth_hdr, uint8_t *broadcast_addr, int interface)
{
	// Get interface MAC
	uint8_t *interface_MAC = malloc(MAC_ADDR_SIZE);
	get_interface_mac(interface, interface_MAC);

	// See if the destination MAC is either broadcast address or router MAC
	if (compare_MAC(eth_hdr->ether_dhost, broadcast_addr) == -1 &&
		compare_MAC(eth_hdr->ether_dhost, interface_MAC) == -1)
	{
		printf("Destination is not correct.\n");
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

		// Make a separate dynamically allocated packet
		char *packet = malloc(MAX_PACKET_LEN);
		memmove(packet, buf, MAX_PACKET_LEN);

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be converted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// Handle IP protocol case
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			// L2 Validation
			if (validate_L2(eth_hdr, broadcast_addr, interface) == -1)
				continue;

			// Handle IP protocol
			if (handle_ipv4(packet, interface, len, arp_cache,
							&arp_cache_size, packet_queue, rtable, &rtable_size) == -1)
				continue;
		}

		// Handle ARP protocol case
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
		{
			handle_arp(packet, arp_cache, &arp_cache_size, packet_queue, rtable, &rtable_size, len, interface);
		}
	}

	free_resources(&rtable, &arp_cache, &broadcast_addr);
	return 0;
}
