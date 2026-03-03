#include "tracker.h"
#include <iostream>
#include <algorithm>

using namespace std;

struct TcpSessionKey
{
    uint32_t ip1;
    uint32_t ip2;
    uint16_t port1;
    uint16_t port2;

    bool operator==(const TcpSessionKey& other) const
    {
        return ip1 == other.ip1 &&
            ip2 == other.ip2 &&
            port1 == other.port1 &&
            port2 == other.port2;
    }
};

struct KeyHasher
{
    size_t operator()(const TcpSessionKey& k) const
    {
        return hash<uint32_t>()(k.ip1) ^
            hash<uint32_t>()(k.ip2) ^
            hash<uint16_t>()(k.port1) ^
            hash<uint16_t>()(k.port2);
    }
};

enum class TcpState
{
    NEW,
    SYN_SEEN,
    SYN_ACK_SEEN,
    ESTABLISHED,
    FIN1,
    FIN2,
    CLOSED,
    BROKEN
};

struct TcpSession
{
    TcpState state = TcpState::NEW;
    bool syn = false;
    bool syn_ack = false;
    bool ack = false;
    bool fin1 = false;
    bool fin2 = false;
    bool broken = false;

    vector<RawPacket> packets;
};

static unordered_map<TcpSessionKey, TcpSession, KeyHasher> sessions;

static TcpSessionKey makeKey(uint32_t s_ip, uint32_t d_ip,
    uint16_t s_port, uint16_t d_port)
{
    if (s_ip < d_ip || (s_ip == d_ip && s_port < d_port))
        return { s_ip, d_ip, s_port, d_port };
    else
        return { d_ip, s_ip, d_port, s_port };
}

SessionResult processTcpPacket(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    const tcphdr* tcp,
    const u_char* full_packet,
    const pcap_pkthdr* header,
    CompletedSession& out_session
)
{
    TcpSessionKey key = makeKey(src_ip, dst_ip, src_port, dst_port);

    auto& session = sessions[key];

    RawPacket pkt;
    pkt.header = *header;
    pkt.data.assign(full_packet, full_packet + header->len);
    session.packets.push_back(move(pkt));

    bool syn = tcp->syn;
    bool ack = tcp->ack;
    bool fin = tcp->fin;
    bool rst = tcp->rst;

    if (rst)
    {
        session.broken = true;
        session.state = TcpState::BROKEN;

        cout << "[TRACKER] TCP session BROKEN (RST)\n";

        sessions.erase(key);
        return SessionResult::BROKEN;
    }

    if (syn && !ack)
    {
        session.syn = true;
        session.state = TcpState::SYN_SEEN;
    }
    else if (syn && ack)
    {
        if (session.syn)
        {
            session.syn_ack = true;
            session.state = TcpState::SYN_ACK_SEEN;
        }
    }
    else if (ack && session.syn && session.syn_ack && !session.ack)
    {
        session.ack = true;
        session.state = TcpState::ESTABLISHED;

        cout << "[TRACKER] TCP ESTABLISHED\n";
    }

    if (fin && session.state == TcpState::ESTABLISHED)
    {
        if (!session.fin1)
        {
            session.fin1 = true;
            session.state = TcpState::FIN1;
        }
        else if (!session.fin2)
        {
            session.fin2 = true;
            session.state = TcpState::FIN2;
        }
    }

    if (session.fin1 && session.fin2)
    {
        session.state = TcpState::CLOSED;

        cout << "[TRACKER] TCP session COMPLETE\n";

        out_session.packets = move(session.packets);

        sessions.erase(key);

        return SessionResult::COMPLETE;
    }

    return SessionResult::IN_PROGRESS;
}