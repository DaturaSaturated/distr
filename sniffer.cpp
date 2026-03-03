#include <iostream>
#include <fstream>
#include <pcap.h>
#include "parser.h"


using namespace std;

bool argCheck(bool incorrect_arg, int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Enter one argument: path to pcap file" << endl;
        return true;
    }
    ifstream file(argv[1]);
    if (!file.is_open()) {
        cout << "The file path is incorrect or there are insufficient rights" << endl;
        return true;
    }
    return false;
}


int readFile(int argc, char* argv[]) {
    bool incorrect_arg = true;
    if (argCheck(incorrect_arg, argc, argv)) {
        return 0;
    }
    else {
        cout << "File was successfully opened" << endl;
    }
    return 1;
 }




int readPCAP(char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);

    if (!handle) {
        cerr << errbuf << endl;
        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* data;

    int counter = 0;

    while (pcap_next_ex(handle, &header, &data) >= 0) {
        counter++;
        protoDef(data, header->len, header);
        cout << "Frame " << counter << ": " << header->len << " bytes" << endl;
    }

    pcap_close(handle);

    return 0;
}

