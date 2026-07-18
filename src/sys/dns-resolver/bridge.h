#ifndef MOTOR_DNS_RESOLVER_BRIDGE_H
#define MOTOR_DNS_RESOLVER_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

enum motor_dns_bridge_family {
	MOTOR_DNS_BRIDGE_V4 = 1,
	MOTOR_DNS_BRIDGE_V6 = 2,
	MOTOR_DNS_BRIDGE_ANY = 3,
};

enum motor_dns_bridge_status {
	MOTOR_DNS_BRIDGE_OK = 0,
	MOTOR_DNS_BRIDGE_NOT_FOUND = 1,
	MOTOR_DNS_BRIDGE_TEMPORARY_FAILURE = 2,
	MOTOR_DNS_BRIDGE_OUT_OF_MEMORY = 3,
	MOTOR_DNS_BRIDGE_UNSUPPORTED_FAMILY = 4,
	MOTOR_DNS_BRIDGE_TIMED_OUT = 5,
	MOTOR_DNS_BRIDGE_SYSTEM = 6,
	MOTOR_DNS_BRIDGE_RESOLVER_FAILURE = 7,
	MOTOR_DNS_BRIDGE_INVALID_REQUEST = 8,
};

struct motor_dns_bridge_addr {
	uint8_t family;
	uint8_t reserved[3];
	uint8_t bytes[16];
};

int motor_dns_lookup(
		const uint8_t *name,
		size_t name_len,
		uint8_t family,
		struct motor_dns_bridge_addr *out,
		size_t out_capacity,
		size_t *out_len,
		uint8_t *out_truncated);

#endif

