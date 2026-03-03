#pragma once
#include <pcap.h>
#include "tracker.h"

void startHandlers();

void stopHandlers();

void handleFtpControl(const u_char* data, uint32_t len);
void handleFtpData(const u_char* data, uint32_t len);
void handleUdpPacket(const u_char* data, uint32_t len);
void handleOtherIp(const u_char* data, uint32_t len);
void handleTcpComplete(const CompletedSession& session);
void handleTcpBroken();