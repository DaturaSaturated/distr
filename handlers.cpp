#include "handlers.h"
#include <pcap.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <sys/time.h>

using namespace std;


static queue<RawPacket> q1, q2, q4;
static queue<CompletedSession> q3;

static mutex m1, m2, m3, m4;
static condition_variable cv1, cv2, cv3, cv4;

static atomic<bool> running = true;


static pcap_t* dead_handle = nullptr;
static pcap_dumper_t* d1 = nullptr;
static pcap_dumper_t* d2 = nullptr;
static pcap_dumper_t* d3 = nullptr;
static pcap_dumper_t* d4 = nullptr;

static void initDumpers()
{
    dead_handle = pcap_open_dead(DLT_EN10MB, 65535);
    d1 = pcap_dump_open(dead_handle, "ftp.pcap");
    d2 = pcap_dump_open(dead_handle, "ftp_data.pcap");
    d3 = pcap_dump_open(dead_handle, "tcp_clean.pcap");
    d4 = pcap_dump_open(dead_handle, "other.pcap");
}

static void worker1()
{
    while (running || !q1.empty())
    {
        unique_lock<mutex> lock(m1);
        cv1.wait(lock, [] { return !running || !q1.empty(); });

        while (!q1.empty())
        {
            auto pkt = move(q1.front());
            q1.pop();
            lock.unlock();

            pcap_dump((u_char*)d1, &pkt.header, pkt.data.data());

            lock.lock();
        }
    }
}

static void worker2()
{
    while (running || !q2.empty())
    {
        unique_lock<mutex> lock(m2);
        cv2.wait(lock, [] { return !running || !q2.empty(); });

        while (!q2.empty())
        {
            auto pkt = move(q2.front());
            q2.pop();
            lock.unlock();

            pcap_dump((u_char*)d2, &pkt.header, pkt.data.data());

            lock.lock();
        }
    }
}

static void worker3()
{
    while (running || !q3.empty())
    {
        unique_lock<mutex> lock(m3);
        cv3.wait(lock, [] { return !running || !q3.empty(); });

        while (!q3.empty())
        {
            auto sess = move(q3.front());
            q3.pop();
            lock.unlock();

            for (auto& pkt : sess.packets)
                pcap_dump((u_char*)d3, &pkt.header, pkt.data.data());

            lock.lock();
        }
    }
}

static void worker4()
{
    while (running || !q4.empty())
    {
        unique_lock<mutex> lock(m4);
        cv4.wait(lock, [] { return !running || !q4.empty(); });

        while (!q4.empty())
        {
            auto pkt = move(q4.front());
            q4.pop();
            lock.unlock();

            pcap_dump((u_char*)d4, &pkt.header, pkt.data.data());

            lock.lock();
        }
    }
}


static thread t1, t2, t3, t4;

void startHandlers()
{
    initDumpers();

    t1 = thread(worker1);
    t2 = thread(worker2);
    t3 = thread(worker3);
    t4 = thread(worker4);
}

void stopHandlers()
{
    running = false;

    cv1.notify_all();
    cv2.notify_all();
    cv3.notify_all();
    cv4.notify_all();

    t1.join();
    t2.join();
    t3.join();
    t4.join();

    pcap_dump_close(d1);
    pcap_dump_close(d2);
    pcap_dump_close(d3);
    pcap_dump_close(d4);
    pcap_close(dead_handle);
}


static RawPacket makePacket(const u_char* data, uint32_t len)
{
    RawPacket pkt;
    pkt.header.caplen = len;
    pkt.header.len = len;
    gettimeofday(&pkt.header.ts, nullptr);
    pkt.data.assign(data, data + len);
    return pkt;
}

void handleFtpControl(const u_char* data, uint32_t len)
{
    auto pkt = makePacket(data, len);
    {
        lock_guard<mutex> lock(m1);
        q1.push(move(pkt));
    }
    cv1.notify_one();
}

void handleFtpData(const u_char* data, uint32_t len)
{
    auto pkt = makePacket(data, len);
    {
        lock_guard<mutex> lock(m2);
        q2.push(move(pkt));
    }
    cv2.notify_one();
}

void handleOtherIp(const u_char* data, uint32_t len)
{
    auto pkt = makePacket(data, len);
    {
        lock_guard<mutex> lock(m4);
        q4.push(move(pkt));
    }
    cv4.notify_one();
}

void handleUdpPacket(const u_char* data, uint32_t len)
{
    handleOtherIp(data, len);
}

void handleTcpComplete(const CompletedSession& session)
{
    {
        lock_guard<mutex> lock(m3);
        q3.push(session);
    }
    cv3.notify_one();
}

void handleTcpBroken() {}