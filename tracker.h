#pragma once
#include <pcap.h>
#include <netinet/tcp.h>
#include <vector>
#include <unordered_map>
#include <cstdint>

struct RawPacket
{
    pcap_pkthdr header;
    std::vector<u_char> data;
};

enum class SessionResult
{
    IN_PROGRESS,
    COMPLETE,
    BROKEN
};

struct CompletedSession
{
    std::vector<RawPacket> packets;
};

SessionResult processTcpPacket(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    const tcphdr* tcp,
    const u_char* full_packet,
    const pcap_pkthdr* header,
    CompletedSession& out_session
);