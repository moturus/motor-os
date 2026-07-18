#include "bridge.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

_Static_assert(sizeof(struct motor_dns_bridge_addr) == 20,
		"Rust and C address layouts differ");

#define MOTOR_DNS_MAX_NAME_LEN 253

static int map_gai_error(int error) {
	switch (error) {
		case 0:
			return MOTOR_DNS_BRIDGE_OK;
		case EAI_NONAME:
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
		case EAI_NODATA:
#endif
			return MOTOR_DNS_BRIDGE_NOT_FOUND;
		case EAI_AGAIN:
			return MOTOR_DNS_BRIDGE_TEMPORARY_FAILURE;
		case EAI_MEMORY:
			return MOTOR_DNS_BRIDGE_OUT_OF_MEMORY;
		case EAI_FAMILY:
#ifdef EAI_ADDRFAMILY
		case EAI_ADDRFAMILY:
#endif
			return MOTOR_DNS_BRIDGE_UNSUPPORTED_FAMILY;
		case EAI_SYSTEM:
			return errno == ETIMEDOUT
				? MOTOR_DNS_BRIDGE_TIMED_OUT
				: MOTOR_DNS_BRIDGE_SYSTEM;
		default:
			return MOTOR_DNS_BRIDGE_RESOLVER_FAILURE;
	}
}

static int same_address(
		const struct motor_dns_bridge_addr *left,
		const struct motor_dns_bridge_addr *right) {
	if (left->family != right->family)
		return 0;
	size_t bytes = left->family == MOTOR_DNS_BRIDGE_V4 ? 4 : 16;
	return !memcmp(left->bytes, right->bytes, bytes);
}

static void append_address(
		const struct addrinfo *entry,
		struct motor_dns_bridge_addr *out,
		size_t out_capacity,
		size_t *out_len,
		uint8_t *out_truncated) {
	struct motor_dns_bridge_addr address = {0};
	if (entry->ai_family == AF_INET
			&& entry->ai_addrlen >= sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *addr =
			(const struct sockaddr_in *)entry->ai_addr;
		address.family = MOTOR_DNS_BRIDGE_V4;
		memcpy(address.bytes, &addr->sin_addr, 4);
	} else if (entry->ai_family == AF_INET6
			&& entry->ai_addrlen >= sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *addr =
			(const struct sockaddr_in6 *)entry->ai_addr;
		address.family = MOTOR_DNS_BRIDGE_V6;
		memcpy(address.bytes, &addr->sin6_addr, 16);
	} else {
		return;
	}

	for (size_t index = 0; index < *out_len; ++index) {
		if (same_address(&address, &out[index]))
			return;
	}
	if (*out_len == out_capacity) {
		*out_truncated = 1;
		return;
	}
	out[(*out_len)++] = address;
}

static int lookup_family(
		const char *name,
		int family,
		struct motor_dns_bridge_addr *out,
		size_t out_capacity,
		size_t *out_len,
		uint8_t *out_truncated) {
	struct addrinfo hints = {0};
	hints.ai_flags = 0;
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *result = NULL;
	int error = getaddrinfo(name, NULL, &hints, &result);
	if (error)
		return map_gai_error(error);

	for (const struct addrinfo *entry = result; entry; entry = entry->ai_next)
		append_address(entry, out, out_capacity, out_len, out_truncated);
	freeaddrinfo(result);

	return *out_len ? MOTOR_DNS_BRIDGE_OK : MOTOR_DNS_BRIDGE_NOT_FOUND;
}

static int merge_failures(int v4_status, int v6_status) {
	if (v4_status == MOTOR_DNS_BRIDGE_TEMPORARY_FAILURE
			|| v6_status == MOTOR_DNS_BRIDGE_TEMPORARY_FAILURE)
		return MOTOR_DNS_BRIDGE_TEMPORARY_FAILURE;
	if (v4_status == MOTOR_DNS_BRIDGE_TIMED_OUT
			|| v6_status == MOTOR_DNS_BRIDGE_TIMED_OUT)
		return MOTOR_DNS_BRIDGE_TIMED_OUT;
	if (v4_status == MOTOR_DNS_BRIDGE_OUT_OF_MEMORY
			|| v6_status == MOTOR_DNS_BRIDGE_OUT_OF_MEMORY)
		return MOTOR_DNS_BRIDGE_OUT_OF_MEMORY;
	if (v4_status == MOTOR_DNS_BRIDGE_SYSTEM
			|| v6_status == MOTOR_DNS_BRIDGE_SYSTEM)
		return MOTOR_DNS_BRIDGE_SYSTEM;
	if (v4_status == MOTOR_DNS_BRIDGE_RESOLVER_FAILURE
			|| v6_status == MOTOR_DNS_BRIDGE_RESOLVER_FAILURE)
		return MOTOR_DNS_BRIDGE_RESOLVER_FAILURE;
	if (v4_status == MOTOR_DNS_BRIDGE_NOT_FOUND
			&& v6_status == MOTOR_DNS_BRIDGE_NOT_FOUND)
		return MOTOR_DNS_BRIDGE_NOT_FOUND;
	return MOTOR_DNS_BRIDGE_UNSUPPORTED_FAMILY;
}

int motor_dns_lookup(
		const uint8_t *name,
		size_t name_len,
		uint8_t family,
		struct motor_dns_bridge_addr *out,
		size_t out_capacity,
		size_t *out_len,
		uint8_t *out_truncated) {
	if (!name || !out_len || !out_truncated || (!out && out_capacity)
			|| !name_len || name_len > MOTOR_DNS_MAX_NAME_LEN
			|| memchr(name, '\0', name_len)
			|| (family != MOTOR_DNS_BRIDGE_V4
				&& family != MOTOR_DNS_BRIDGE_V6
				&& family != MOTOR_DNS_BRIDGE_ANY)) {
		return MOTOR_DNS_BRIDGE_INVALID_REQUEST;
	}

	*out_len = 0;
	*out_truncated = 0;
	char terminated[MOTOR_DNS_MAX_NAME_LEN + 1];
	memcpy(terminated, name, name_len);
	terminated[name_len] = '\0';

	// Avoid turning a numeric literal of the other family into a DNS query.
	struct in_addr numeric_v4;
	struct in6_addr numeric_v6;
	int is_v4 = inet_pton(AF_INET, terminated, &numeric_v4) == 1;
	int is_v6 = !is_v4 && inet_pton(AF_INET6, terminated, &numeric_v6) == 1;
	if (is_v4) {
		if (family == MOTOR_DNS_BRIDGE_V6)
			return MOTOR_DNS_BRIDGE_NOT_FOUND;
		return lookup_family(terminated, AF_INET, out, out_capacity, out_len,
				out_truncated);
	}
	if (is_v6) {
		if (family == MOTOR_DNS_BRIDGE_V4)
			return MOTOR_DNS_BRIDGE_NOT_FOUND;
		return lookup_family(terminated, AF_INET6, out, out_capacity, out_len,
				out_truncated);
	}

	if (family == MOTOR_DNS_BRIDGE_V4)
		return lookup_family(terminated, AF_INET, out, out_capacity, out_len,
				out_truncated);
	if (family == MOTOR_DNS_BRIDGE_V6)
		return lookup_family(terminated, AF_INET6, out, out_capacity, out_len,
				out_truncated);

	// Stable combined ordering: all unique IPv4 results, then IPv6 results.
	int v4_status = lookup_family(terminated, AF_INET, out, out_capacity,
			out_len, out_truncated);
	int v6_status = lookup_family(terminated, AF_INET6, out, out_capacity,
			out_len, out_truncated);
	if (*out_len)
		return MOTOR_DNS_BRIDGE_OK;
	return merge_failures(v4_status, v6_status);
}

