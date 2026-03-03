#pragma once

#include <cstdint>

int protoDef(const u_char* data,
    uint32_t len,
    const pcap_pkthdr* header);