#ifndef __ETHER_SNIFFER_H__
#define __ETHER_SNIFFER_H__

#include <arp_format.h>
#include <lockedhash.hpp>
#include <string>
#include <unordered_map>
#include <vector>
#include <wipsable.h>

typedef struct net_v4_conf {
  uint32_t _start_ip;
  uint32_t _end_ip;
  uint32_t _netmask;
  uint32_t _network;
} net_v4_conf_t;

class NetClient {
private:
  uint32_t _client_ip;
  uint8_t _mac[6];
  size_t _detected;
  time_t _last_seen;

public:
  NetClient(const uint8_t *mac) { memcpy(_mac, mac, sizeof(_mac)); }
  const uint8_t *mac() const { return _mac; }
  uint32_t client_ip() const { return _client_ip; }
  size_t detected() const { return _detected; }
  time_t last_seen() const { return _last_seen; }
};

struct NetClientHash {
  size_t operator()(NetClient const &t) const noexcept {
    auto mac = t.mac();
    return ((mac[0] + mac[5]) ^ (mac[1] + mac[4]) ^ (mac[2] + mac[3]));
  }
};

struct NetClientMakeKey {
  const uint8_t *operator()(NetClient const &t) const noexcept { //
    return t.mac();
  }
};

class EtherSniffer : public Wipsable {
private:
  std::vector<net_v4_conf_t> _net_configs;
  std::unordered_map<uint32_t, uint8_t *> _ip_mac_map;
  std::string _ifname;
  LockedHash<const uint8_t *, NetClient, NetClientHash, NetClientMakeKey>
      *_net_clients;

private:
  static void sniff_callback(int fd, short events, void *arg);
  static int create_sniff_socket(const std::string &ifname);

public:
  EtherSniffer(const std::string &ifname);
  virtual ~EtherSniffer();
  void add_net_config(const net_v4_conf_t &conf);

public:
  bool run();
  const std::string name();
};

#endif