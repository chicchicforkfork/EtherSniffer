#include <arpa/inet.h>
#include <errno.h>
#include <ether_sniffer.h>
#include <event.h>
#include <event2/listener.h>
#include <fcntl.h>
#include <iostream>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <linux/wireless.h>
#include <netutil.hpp>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;

EtherSniffer::EtherSniffer(const std::string &ifname) {
  _ifname = ifname;
  _net_client_hash = new LockedHash<const uint8_t *, NetClient, NetClientHash,
                                    NetClientMakeKey>(4096, 60 * 2);
}

EtherSniffer::~EtherSniffer() { //
  delete _net_client_hash;
}

int EtherSniffer::create_sniff_socket(const std::string &ifname) {
  int sockfd = -1;

  // create broadcast socket
  {
    static int on = 1;
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
      goto err;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
      goto err;
    }
  }

  // nonblock
  { //
    evutil_make_socket_nonblocking(sockfd);
  }

  // promisc
  {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name) - 1);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
      goto err;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1) {
      goto err;
    }
  }

  // bind
  {
    struct sockaddr_ll sll;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name) - 1);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1) {
      goto err;
    }
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
      goto err;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
      goto err;
    }
  }
  return sockfd;

err:
  if (sockfd != -1) {
    close(sockfd);
  }
  return sockfd;
}

void EtherSniffer::add_net_config(const net_v4_conf_t &conf) {
  _net_configs.push_back(conf);
}

const string EtherSniffer::name() { //
  return "ether_sniffer";
}

LockedHash<const uint8_t *, NetClient, NetClientHash, NetClientMakeKey> *
EtherSniffer::net_client_hash() {
  return _net_client_hash;
}

bool EtherSniffer::run() {
  struct event_base *evbase;
  struct event *evlisten;
  int sniff_fd;

  sniff_fd = create_sniff_socket(_ifname);
  evbase = event_base_new();

  evlisten = event_new(evbase,                       //
                       sniff_fd,                     //
                       EV_READ | EV_PERSIST,         //
                       EtherSniffer::sniff_callback, //
                       this);

  event_add(evlisten, NULL);
  event_base_dispatch(evbase);
}

void EtherSniffer::sniff_callback(int fd, short events, void *arg) {
  (void)events;
  auto sniffer = (EtherSniffer *)arg;
  auto net_client_hash = sniffer->net_client_hash();
  uint8_t payload[sizeof(NetUtil::arp_t)] = {0};
  auto ether = (NetUtil::ethhdr_t *)payload;
  size_t rbytes;
  NetClient net_client;

  rbytes = recv(fd, &payload, sizeof(payload), 0);
  if ((rbytes <= 0) || (rbytes < sizeof(NetUtil::ethhdr_t))) {
    return;
  }
  if (NetUtil::mac::multicast(ether->h_source) || //
      NetUtil::mac::null(ether->h_source)) {
    return;
  }

  switch (ntohs(ether->h_proto)) {
  case ETH_P_8021Q:
    break;
  case ETH_P_ARP: //
  {
    auto arp = (NetUtil::arp_t *)payload;
    switch (ntohs(arp->operation)) {
    case ARPOP_REPLY:
    case ARPOP_REQUEST:
      net_client.mac(arp->sHaddr);
      net_client.ip(arp->sInaddr);
      if (NetUtil::ip::null(net_client.ip()) || //
          NetUtil::ip::broadcast(net_client.ip())) {
        return;
      }
      if (NetUtil::arp::gratuitous(arp)) {
        //
      }
      break;
    default:
      return;
    }
    break;
  }
  case ETH_P_IP:
    break;
  default:
    return;
  }
}