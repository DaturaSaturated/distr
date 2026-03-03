#include "tracker.h"
#include "handlers.h"
#include <pcap.h>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <chrono>
#include <iomanip>
#include <sstream>


using namespace std;

int protoDef(const u_char* data, uint32_t len, const pcap_pkthdr* header) {
    int offset = 0;

    const ether_header* eth = (const ether_header*)data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;

    offset += sizeof(ether_header);

    const iphdr* ip = (const iphdr*)(data + offset);
    offset += ip->ihl * 4;

    if (ip->protocol == IPPROTO_TCP)
    {
        if (len < offset + sizeof(tcphdr))
            return 0;

        const tcphdr* tcp = (const tcphdr*)(data + offset);

        uint16_t sport = ntohs(tcp->source);
        uint16_t dport = ntohs(tcp->dest);

        offset += tcp->doff * 4;

        bool ftp_control = (sport == 21 || dport == 21);
        bool ftp_data = (sport == 20 || dport == 20);

        if (ftp_control)
            handleFtpControl(data, header->len);
        else if (ftp_data)
            handleFtpData(data, header->len);
        else
        {
            CompletedSession completed;

            SessionResult result = processTcpPacket(
                ip->saddr,
                ip->daddr,
                sport,
                dport,
                tcp,
                data,
                header,
                completed
            );

            if (result == SessionResult::COMPLETE)
            {
                handleTcpComplete(completed);
            }
            else if (result == SessionResult::BROKEN)
            {
                handleTcpBroken();
            }
        }
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        if (len < offset + sizeof(udphdr))
            return 0;

        const udphdr* udp = (const udphdr*)(data + offset);

        uint16_t sport = ntohs(udp->source);
        uint16_t dport = ntohs(udp->dest);

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

        if (sport >= 20000 && sport <= 25000)
        {
            auto now = std::chrono::system_clock::now();
            std::time_t tt = std::chrono::system_clock::to_time_t(now);
            std::tm tm = *std::localtime(&tt);

            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

            std::cout << "Обработчик 3: " << oss.str()
                << " пакет UDP "
                << src_ip << ":" << sport
                << " -> "
                << dst_ip << ":" << dport
                << " игнорируется"
                << std::endl;

            return 0;
        }

        handleUdpPacket(data, header->len);
    }
    else
    {
        handleOtherIp(data, header->len);
    }

    return 0;

}