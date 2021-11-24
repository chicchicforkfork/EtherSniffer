#ifndef __ARP_FORMAT_H__
#define __ARP_FORMAT_H__

#include <linux/if_ether.h>
#include <stdint.h>

struct vethhdr {
  uint8_t h_dest[6];
  uint8_t h_source[6];
  uint16_t h_vlan_proto;
  uint16_t h_vlan_tag;
  uint16_t h_proto;
} __attribute__((packed));

struct arp {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t operation;
  uint8_t sHaddr[6];
  uint8_t sInaddr[4];
  uint8_t tHaddr[6];
  uint8_t tInaddr[4];
  uint8_t pad[18];
} __attribute__((packed));

struct arp_1Q {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t operation;
  uint8_t sHaddr[6];
  uint8_t sInaddr[4];
  uint8_t tHaddr[6];
  uint8_t tInaddr[4];
  uint8_t pad[14];
} __attribute__((packed));

#endif