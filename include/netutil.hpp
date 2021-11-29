#ifndef __NET_UTILS_H__
#define __NET_UTILS_H__

#include <arp_format.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <string.h>

namespace NetUtil {

typedef struct ethhdr_t {
  uint8_t h_dest[ETH_ALEN];   /* destination eth addr	*/
  uint8_t h_source[ETH_ALEN]; /* source ether addr	*/
  __be16 h_proto;             /* packet type ID field	*/
} __attribute__((packed)) ethhdr_t;

typedef struct vethhdr_t {
  uint8_t h_dest[ETH_ALEN];
  uint8_t h_source[ETH_ALEN];
  uint16_t h_vlan_proto;
  uint16_t h_vlan_tag;
  uint16_t h_proto;
} __attribute__((packed)) vethhdr_t;

typedef struct arp_t {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t operation;
  uint8_t sHaddr[ETH_ALEN];
  uint8_t sInaddr[4];
  uint8_t tHaddr[ETH_ALEN];
  uint8_t tInaddr[4];
  uint8_t pad[18];
} __attribute__((packed)) arp_t;

typedef struct arp_1q_t {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t operation;
  uint8_t sHaddr[ETH_ALEN];
  uint8_t sInaddr[4];
  uint8_t tHaddr[ETH_ALEN];
  uint8_t tInaddr[4];
  uint8_t pad[14];
} __attribute__((packed)) arp_1q_t;

class mac {
public:
  static bool null(uint8_t *mac) {
    return memcmp(mac, "\x00\x00\x00\x00\x00\x00", ETH_ALEN) == 0;
  }
  static bool broadcast(uint8_t *mac) {
    return memcmp(mac, "\xff\xff\xff\xff\xff\xff", ETH_ALEN) == 0;
  }
  static bool multicast(uint8_t *mac) { return (mac[0] & 0x01); }
  static bool equal(const uint8_t *mac1, const uint8_t *mac2) {
    return memcmp(mac1, mac2, ETH_ALEN);
  }
};

class ip {
public:
  static bool null(uint32_t ip) { return (ip == 0); }
  static bool broadcast(uint32_t ip) { return (ip == (int32_t)-1); }
  static bool equal(uint32_t ip1, uint32_t ip2) { return ip1 == ip2; }
  static bool equal(const uint8_t *ip1, const uint8_t *ip2) {
    return memcmp(ip1, ip2, 4);
  }
};

class arp {
public:
  static bool gratuitous(const struct arp_t *arp) {
    return (memcmp(arp->sInaddr, arp->tInaddr, 4) == 0) && //
           (memcmp(arp->sHaddr, arp->tHaddr, ETH_ALEN) == 0);
  }
};

class wips_arp {
public:
  static uint32_t whois(const struct arp_t *arp) {
    return ntohl(*(uint32_t *)arp->pad);
  }
};

}; // namespace NetUtil

#endif