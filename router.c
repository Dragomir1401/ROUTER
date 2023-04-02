#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stddef.h>
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
#define ETH_P_IP 0x0800
#define ARP_REQUEST 1
#define ICMP_OVER 64
#define ICMP_ECHO 8
#define ERROR -1
#define ECHO 0

void setup(struct route_table_entry **rtable, uint_fast32_t *rtable_size,
		   struct arp_entry **arp_cache, uint_fast32_t *arp_cache_size, uint8_t **broadcast_addr,
		   queue *packet_queue, char *path)
{

	// Alloc a struct for the routes table
	*rtable = calloc(MAX_ENTRIES_RTABLE, sizeof(struct route_table_entry));
	DIE(*rtable == NULL, "Error at allocating memory for rtable.\n");

	// Read rtable to store routes
	*rtable_size = read_rtable(path, *rtable);
	DIE(rtable_size < 0, "Rtable is empty.\n");

	// Sort table entries using built in quick sort with comparator which compares:
	// -1- masks
	// -2- for the same mask -> prefixes
	qsort(*rtable, *rtable_size, sizeof(struct route_table_entry), compare_rtable_entries);

	// Create ARP cache to store already found addresses to make a more efficient implementation
	*arp_cache = calloc(MAX_ENTRIES_ARP_CACHE, sizeof(struct arp_entry));
	DIE(*arp_cache == NULL, "Error at allocating memory for ARP cache.\n");

	// Set initial size to 0
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
	// Empty memory adresses
	free(*rtable);
	free(*arp_cache);
	free(*broadcast_addr);
}

char *mac_to_str(uint8_t mac[6])
{
	// Transform MAC to string for printable
	static char str[18];
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return str;
}

void print_packet_info(char message[30], struct in_addr src_ip, uint8_t *src_mac, struct in_addr dst_ip, uint8_t *dst_mac, int interface)
{
	// Helper printer function
	printf("%s\n", message);
	printf("Source      --- %s .\n", inet_ntoa(src_ip));
	printf("MAC source  --- %s\n", mac_to_str(src_mac));
	printf("Destination --- %s.\n", inet_ntoa(dst_ip));
	printf("MAC destin  --- %s\n", mac_to_str(dst_mac));
	printf("Via interface %d.\n\n", interface);
}

void print_route_info(char message[30], struct in_addr src_ip, struct in_addr next_hop)
{
	// Helper printer function
	printf("%s\n", message);
	printf("Source   --- %s.\n", inet_ntoa(src_ip));
	printf("Next hop --- %s from the route table.\n\n", inet_ntoa(next_hop));
}

void add_arp_cache_entry(struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size, struct arp_entry *new_entry)
{
	// Search to see if entry already exits
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

	// It does exit so exit
	if (cnt == -1)
	{
		return;
	}

	// Print message
	struct in_addr ip_addr;
	ip_addr.s_addr = new_entry->ip;
	printf("Adding entry in arp cache: ip: %s mac: %s.\n\n", inet_ntoa(ip_addr), mac_to_str(new_entry->mac));

	// Insert the new entry at the end and increase size
	arp_cache[(*arp_cache_size)] = *new_entry;
	(*arp_cache_size)++;
}

int binary_search(struct route_table_entry *rtable, uint32_t searched_ip, int left, int right)
{
	// Function to binary search for LPM in the route table
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
	// Try to find entry in the route table and return -1 if it does not exit
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
	// Search int the arp cache for next hop MAC
	for (int arp_cnt = 0; arp_cnt < *arp_cache_size; arp_cnt++)
	{
		if (route_entry->next_hop == arp_cache[arp_cnt].ip)
			update_packet(&route_entry, arp_cache[arp_cnt], q);
	}
}

void pop_from_queue(queue packet_queue, struct arp_entry *arp_cache, uint_fast32_t arp_cache_size,
					struct route_table_entry *rtable, uint_fast32_t rtable_size, int len)
{
	// Check to see if queue has elements
	if (queue_empty(packet_queue))
	{
		return;
	}

	// Extract packet and headers
	char *buf = malloc(MAX_PACKET_LEN);
	buf = (char *)queue_deq(packet_queue);
	struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// Search entry in route table
	struct route_table_entry *entry = LPM(iphdr->daddr, rtable, rtable_size);

	// Print route if found
	struct in_addr src_ip;
	src_ip.s_addr = iphdr->saddr;
	print_route_info("Found route for packet dequeued:", src_ip, *(struct in_addr *)&entry->next_hop);

	// Search for next hop and send to it if found
	for (int cnt = 0; cnt < arp_cache_size; cnt++)
	{
		if (entry->next_hop == arp_cache[cnt].ip)
		{
			// Extract Ethernet header
			struct ether_header *ethhdr = (struct ether_header *)buf;

			// Extract new MAC
			uint8_t *MAC = malloc(MAC_ADDR_SIZE);
			get_interface_mac(entry->interface, MAC);

			// Change source MAC and destination MAC
			memmove(ethhdr->ether_shost, MAC, MAC_ADDR_SIZE);
			memmove(ethhdr->ether_dhost, arp_cache[cnt].mac, MAC_ADDR_SIZE);

			struct in_addr src_ip;
			src_ip.s_addr = iphdr->saddr;
			print_packet_info("Sending packet from queue...", src_ip, ethhdr->ether_shost, *(struct in_addr *)&entry->next_hop, ethhdr->ether_dhost, entry->interface);

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
	// Handle ARP reply
	fprintf(stderr, "Handling ARP reply...\n");

	// Print source IP address
	char source_addr_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(arp_hdr->spa), source_addr_str, INET_ADDRSTRLEN);
	fprintf(stderr, "Source IP address: %s\n", source_addr_str);

	// Print next hop IP address
	char next_hop_addr_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(arp_hdr->tpa), next_hop_addr_str, INET_ADDRSTRLEN);
	fprintf(stderr, "Next hop IP address: %s\n", next_hop_addr_str);

	// Create a new ARP cache entry and add it to arp cache
	struct arp_entry new_entry = {
		.ip = arp_hdr->spa,
	};

	memmove(new_entry.mac, arp_hdr->sha, MAC_ADDR_SIZE);
	add_arp_cache_entry(arp_cache, arp_cache_size, &new_entry);

	// Check if the packet can be sent now
	pop_from_queue(packet_queue, arp_cache, *arp_cache_size, rtable, *rtable_size, len);
}

void arp_reply(char *buf, uint8_t *dest_mac, uint8_t *source_mac, uint32_t ip_daddr, uint32_t ip_saddr,
			   int interface, int len)
{
	// Allocate memory for new packet and zero it out
	char *new_packet = calloc(MAX_PACKET_LEN, sizeof(char));

	// Prepare ethernet header
	struct ether_header ethhdr = {
		.ether_type = htons(ETHERTYPE_ARP),
	};
	memmove(ethhdr.ether_shost, source_mac, MAC_ADDR_SIZE);
	memmove(ethhdr.ether_dhost, dest_mac, MAC_ADDR_SIZE);
	memmove(new_packet, &ethhdr, sizeof(struct ether_header));

	// Prepare ARP header
	struct arp_header arphdr = {
		.op = htons(ARP_REPLY),
		.ptype = htons(2048),
		.plen = IP_ADDR_SIZE,
		.htype = htons(1),
		.hlen = MAC_ADDR_SIZE,
	};

	// Set up sendder and reciever MAC's
	memmove(arphdr.sha, source_mac, MAC_ADDR_SIZE);
	memmove(arphdr.tha, dest_mac, MAC_ADDR_SIZE);

	// Set up sendder and reciever ip's
	arphdr.spa = ip_saddr;
	arphdr.tpa = ip_daddr;

	// Put the header in place
	memmove(new_packet + sizeof(struct ether_header), &arphdr, sizeof(struct arp_header));

	// Send packet
	print_packet_info("Sending packet from arp reply...", *(struct in_addr *)&ip_saddr, source_mac, *(struct in_addr *)&ip_daddr, dest_mac, interface);
	send_to_link(interface, new_packet, len);

	// Free memory
	free(new_packet);
}

void arp_request(struct route_table_entry *router_entry, uint8_t *broadcast_addr)
{
	// Prepare Ethernet and ARP headers
	struct ether_header eth_header = {
		.ether_type = htons(ETHERTYPE_ARP),
	};
	struct arp_header arp_header = {
		.htype = htons(1),
		.ptype = htons(ETH_P_IP),
		.hlen = MAC_ADDR_SIZE,
		.plen = sizeof(in_addr_t),
		.op = htons(ARP_REQUEST),
	};

	// Get route MAC
	get_interface_mac(router_entry->interface, eth_header.ether_shost);
	get_interface_mac(router_entry->interface, arp_header.sha);

	// Set destination MAC to broadcast
	memmove(eth_header.ether_dhost, broadcast_addr, MAC_ADDR_SIZE);
	memmove(arp_header.tha, broadcast_addr, MAC_ADDR_SIZE);

	// Get route ip and destination ip to next hop
	arp_header.spa = inet_addr(get_interface_ip(router_entry->interface));
	arp_header.tpa = router_entry->next_hop;

	// Allocate buffer and copy Ethernet and ARP headers
	char *packet_buffer = malloc(MAX_PACKET_LEN);
	DIE(!packet_buffer, "Malloc for new packet buffer.\n");
	memset(packet_buffer, 0, MAX_PACKET_LEN);

	// Put headers in place
	memmove(packet_buffer, &eth_header, sizeof(struct ether_header));
	memmove(packet_buffer + sizeof(struct ether_header), &arp_header, sizeof(struct arp_header));

	// Print info and send the ARP request packet
	printf("Sending ARP request from %s to %s\n",
		   inet_ntoa(*(struct in_addr *)&arp_header.spa),
		   inet_ntoa(*(struct in_addr *)&arp_header.tpa));
	send_to_link(router_entry->interface, packet_buffer, sizeof(struct ether_header) + sizeof(struct arp_header));
}

int handle_arp(char *buf, struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size,
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
		return -1;
	}

	// Request case -> reply with the local interface MAC
	if (arp_hdr->op == htons(1))
	{
		// Get MAC of route
		uint8_t *local_mac = malloc(MAC_ADDR_SIZE);
		get_interface_mac(interface, local_mac);

		// Inverse sender with target MAC
		uint8_t *target_mac = malloc(MAC_ADDR_SIZE);
		memmove(target_mac, arp_hdr->sha, MAC_ADDR_SIZE);

		// Reply to ARP request
		arp_reply(buf, target_mac, local_mac, arp_hdr->spa, arp_hdr->tpa, interface, len);

		// Exit
		return -1;
	}

	return 0;
}

void update_checksum(struct iphdr *iphdr)
{

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
					   struct icmphdr *icmphdr, uint8_t *dest_mac, uint8_t *source_mac, int error_or_echo)
{
	// Create a new packet buffer
	char new_packet[MAX_PACKET_LEN];
	memset(new_packet, 0, MAX_PACKET_LEN);

	// Copy the original headers and data into the new packet buffer
	memmove(new_packet, buf, MAX_PACKET_LEN);

	// Update the MAC addresses in the Ethernet header
	memmove(new_packet, dest_mac, MAC_ADDR_SIZE);
	memmove(new_packet + MAC_ADDR_SIZE, source_mac, MAC_ADDR_SIZE);

	// Update the IP addresses in the IP header
	memmove(new_packet + sizeof(struct ether_header) + offsetof(struct iphdr, daddr), &iphdr->saddr, sizeof(uint32_t));
	memmove(new_packet + sizeof(struct ether_header) + offsetof(struct iphdr, saddr), &iphdr->daddr, sizeof(uint32_t));

	// Update the protocol field in the IP header
	uint8_t protocol = IPPROTO_ICMP;
	memmove(new_packet + sizeof(struct ether_header) + offsetof(struct iphdr, protocol), &protocol, sizeof(uint8_t));

	// Update the total length field in the IP header
	uint16_t total_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	memmove(new_packet + sizeof(struct ether_header) + offsetof(struct iphdr, tot_len), &total_len, sizeof(uint16_t));

	if (error_or_echo == -1)
	// Error case
	{
		printf("Sending ICMP error from %d to %d.\n", iphdr->saddr, iphdr->daddr);

		// Put 64 more bytes over the IP header
		char *over_ip = malloc(ICMP_OVER);
		memmove(over_ip, buf + sizeof(struct ether_header) + sizeof(struct iphdr), ICMP_OVER);

		// Update the ICMP header and add the additional 64 bytes
		memmove(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmphdr, sizeof(struct icmphdr));
		memmove(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), over_ip, ICMP_OVER);

		// Send the new packet
		send_to_link(interface, new_packet, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_OVER);

		return;
	}
	else if (!error_or_echo)
	// Message case
	{
		printf("Sending ICMP echo from %d to %d.\n", iphdr->saddr, iphdr->daddr);

		// Update the ICMP header
		memmove(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr), icmphdr, sizeof(struct icmphdr));

		// Send the new packet
		send_to_link(interface, new_packet, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	}
}

int check_ttl(struct ether_header *ethhdr, struct iphdr *iphdr, char *buf, int interface)
{
	// Throw packages with ttl 0 or 1
	if (iphdr->ttl <= 1)
	{
		printf("Time limit was reached...Dropping package.\n");

		// Save destination MAC for ICMP
		uint8_t *dest_mac = malloc(MAC_ADDR_SIZE);
		memmove(dest_mac, ethhdr->ether_dhost, MAC_ADDR_SIZE);

		uint8_t *source_mac = malloc(MAC_ADDR_SIZE);
		memmove(source_mac, ethhdr->ether_shost, MAC_ADDR_SIZE);

		// Create ICMP header for sending ICMP message
		struct icmphdr *icmphdr = malloc(sizeof(struct icmphdr));
		icmphdr->type = TIME_EXCEEDED;
		icmphdr->code = 0;
		icmphdr->checksum = 0;

		// Set the identifier and sequence number to zero
		icmphdr->un.echo.id = 0;
		icmphdr->un.echo.sequence = 0;

		// Compute the ICMP header checksum
		uint16_t *icmpbuf = (uint16_t *)icmphdr;
		icmphdr->checksum = checksum(icmpbuf, sizeof(struct icmphdr));

		// Send ICMP error
		send_icmp_message(buf, interface, iphdr, ethhdr, icmphdr, source_mac, dest_mac, ERROR);

		free(icmphdr);
		free(dest_mac);
		free(source_mac);

		return -1;
	}

	// Decrement the TTL
	iphdr->ttl--;

	// Update the checksum
	update_checksum(iphdr);
	return 0;
}

int search_ip_arp_cache(struct arp_entry *arp_table, int arp_table_len, uint32_t searched_ip, uint8_t *mac_targeted)
{
	// Search liniar for the next hop MAC in the arp cache
	struct arp_entry *entry;
	for (entry = arp_table; entry < arp_table + arp_table_len; ++entry)
	{
		if (entry->ip == searched_ip)
		{
			memmove(mac_targeted, entry->mac, MAC_ADDR_SIZE);
			return 0;
		}
	}
	return -1;
}

int search_destination(struct iphdr *iphdr, struct ether_header *ethhdr, struct route_table_entry *rtable,
					   uint_fast32_t rtable_size, int *interface, char *buf, struct arp_entry *arp_cache,
					   uint_fast32_t arp_cache_size, int len, queue packet_queue, uint8_t *broadcast_addr)
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

		// Create new ICMP header for error
		struct icmphdr icmp_header = {
			.type = DEST_UNREACH,
			.code = 0,
			.checksum = 0,
		};

		// Calculate the checksum for the ICMP header
		icmp_header.checksum = checksum((uint16_t *)&icmp_header, sizeof(icmp_header));

		// Allocate memory for the source and destination MAC addresses
		uint8_t *dest_mac = malloc(MAC_ADDR_SIZE);
		uint8_t *source_mac = malloc(MAC_ADDR_SIZE);

		// Copy the MAC addresses from the Ethernet header
		memmove(dest_mac, ethhdr->ether_dhost, MAC_ADDR_SIZE);
		memmove(source_mac, ethhdr->ether_shost, MAC_ADDR_SIZE);

		// Send ICMP error message
		send_icmp_message(buf, *interface, iphdr, ethhdr, &icmp_header, source_mac, dest_mac, ERROR);

		// Free the allocated memory for the MAC addresses
		free(dest_mac);
		free(source_mac);

		return -1;
	}

	// Print with correct layout
	print_route_info("Found route in the route table for:", *(struct in_addr *)&iphdr->saddr, *(struct in_addr *)&LPM_addr->next_hop);

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
		memmove(ethhdr->ether_dhost, next_mac, MAC_ADDR_SIZE);

		print_packet_info("Sending packet on found destination:", *(struct in_addr *)&iphdr->saddr,
						  ethhdr->ether_shost, *(struct in_addr *)&iphdr->daddr, ethhdr->ether_dhost, LPM_addr->interface);
		// Send to the found in arp cache address
		*interface = LPM_addr->interface;
		send_to_link(*interface, buf, len);

		// Exit
		return -1;
	}

	// Print packet info
	print_packet_info("Enqueuing package:", *(struct in_addr *)&iphdr->saddr,
					  ethhdr->ether_shost, *(struct in_addr *)&iphdr->daddr, ethhdr->ether_dhost, LPM_addr->interface);

	// Make an ARP request
	arp_request(LPM_addr, broadcast_addr);

	// If we dont find next MAC in arp cache then make an ARP request to find it and add packet in queue
	queue_enq(packet_queue, buf);

	// Exit
	return -1;
}

void icmp_echo(struct iphdr *iphdr, struct ether_header *ethhdr, struct icmphdr *icmphdr,
			   int interface, char *buf)
{
	// Allocate memory for destination and source MAC addresses
	uint8_t *dest_mac = malloc(MAC_ADDR_SIZE);
	uint8_t *source_mac = malloc(MAC_ADDR_SIZE);

	// Copy destination and source MAC addresses
	memmove(dest_mac, ethhdr->ether_dhost, MAC_ADDR_SIZE);
	memmove(source_mac, ethhdr->ether_shost, MAC_ADDR_SIZE);

	// Create new ICMP Header for error
	struct icmphdr new_icmphdr = {
		.code = 0,
		.type = ECHO_REPLY,
		.checksum = 0};
	new_icmphdr.checksum = checksum((uint16_t *)&new_icmphdr, sizeof(struct icmphdr));

	// Send icmp echo
	send_icmp_message(buf, interface, iphdr, ethhdr, &new_icmphdr, source_mac, dest_mac, ECHO);

	// Free memory for destination and source MAC addresses
	free(dest_mac);
	free(source_mac);
}

int handle_ipv4(char *buf, int interface, int len, struct arp_entry *arp_cache, uint_fast32_t *arp_cache_size,
				queue packet_queue, struct route_table_entry *rtable, uint_fast32_t *rtable_size, uint8_t *broadcast_addr)
{
	printf("Entering IPv4 protocol...\n");

	// Extract ethernet header
	struct ether_header *ethhdr = (struct ether_header *)buf;

	// Extract ip header
	struct iphdr *iphdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	print_packet_info("Recieved IP package:", *(struct in_addr *)&iphdr->saddr,
					  ethhdr->ether_shost, *(struct in_addr *)&iphdr->daddr, ethhdr->ether_dhost, interface);

	// Verify the checksum
	if (checksum((void *)iphdr, sizeof(struct iphdr)))
	{
		printf("Checksum test could not be validated.\n");
		return -1;
	}

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

	// Check to see if ttl dropped below 2
	if (check_ttl(ethhdr, iphdr, buf, interface) == -1)
	{
		return -1;
	}

	// Search to see if router has address in route table
	if (search_destination(iphdr, ethhdr, rtable, *rtable_size, &interface,
						   buf, arp_cache, *arp_cache_size, len, packet_queue, broadcast_addr) == -1)
	{
		return -1;
	}

	return 0;
}

int compare_MAC(uint8_t *addr1, uint8_t *addr2)
{
	// Compare 2 MAC addresses
	int i = 0;
	while (i < MAC_ADDR_SIZE && addr1[i] == addr2[i])
	{
		i++;
	}
	if (i == MAC_ADDR_SIZE)
	{
		// They are equal
		return 0;
	}

	// They are not equal
	return -1;
}

int validate_L2(struct ether_header *eth_hdr, uint8_t *broadcast_addr, int interface)
{
	// Verifies if the router itself or the broadcast address are the destination or not

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
		char *packet = calloc(MAX_PACKET_LEN, 1);
		memmove(packet, buf, MAX_PACKET_LEN);

		struct ether_header *eth_hdr = (struct ether_header *)packet;

		// Handle IP protocol case
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			// L2 Validation
			if (validate_L2(eth_hdr, broadcast_addr, interface) == -1)
				continue;

			// Handle IP protocol
			if (handle_ipv4(packet, interface, len, arp_cache,
							&arp_cache_size, packet_queue, rtable, &rtable_size, broadcast_addr) == -1)
				continue;
		}

		// Handle ARP protocol case
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
		{
			if (handle_arp(packet, arp_cache, &arp_cache_size, packet_queue,
						   rtable, &rtable_size, len, interface) == -1)
				continue;
		}
	}

	free_resources(&rtable, &arp_cache, &broadcast_addr);
	return 0;
}