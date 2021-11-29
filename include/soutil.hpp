#ifndef __SO_UTILS_H__
#define __SO_UTILS_H__

#include <stdint.h>
#include <string.h>

class SoUtil {

public:
  static bool nullmac(uint8_t *mac) {
    return memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6) == 0;
  }
  static bool nullmac(uint8_t *mac) {
    return memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6) == 0;
  }
};

#endif