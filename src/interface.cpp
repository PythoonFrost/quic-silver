#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

// Header for parsing the JSON file into the C++, and needed to be downloaded and put them in the same folder first
// simdjson is a JSON parser that is much faster and more efficient compare to other
// To learn more about it https://github.com/simdjson/simdjson?tab=readme-ov-file
#include "simdjson.h"

using namespace std;
const string json_log = "quic_summary_log.json";

// function to print the manual, intrusctions and commands for the program
void print_help() {
    cout << "--- QUIC Monitoring Program using eBPF ---" << endl;
    cout << "Commands:" << endl;
    cout << "  monitor -i <interface> -r <rule>" << endl;
    cout << "  update -r" << endl;
    cout << "  list-interfaces" << endl;
    cout << "  list-rules" << endl;
    cout << "  --help" << endl;
    cout << "\nOptions:" << endl;
    cout << "  -i, --interfaces   Specify network interface(s)" << endl;
    cout << "  -r, --rules        Specify rule(s) or update rules" << endl;
    cout << "  --help             Show this help message" << endl;
}

// printing the network interfaces available on the host, specifically for Windows
// this can be done by using GetAdaptersAddresses function on Windows
// for different OS, different methods could be implemented
void list_interfaces() {
#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "WSAStartup failed." << endl;
        return;
    }

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    // Both IPv4 and IPv6
    ULONG family = AF_UNSPEC;
    // Initial buffer size
    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);

    // Pointer to the buffer
    PIP_ADAPTER_ADDRESSES adapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    // Get adapter addresses from the system
    DWORD ret = GetAdaptersAddresses(family, flags, nullptr, adapterAddresses, &bufferSize);

    // If buffer was too small, resize and try again
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        adapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        ret = GetAdaptersAddresses(family, flags, nullptr, adapterAddresses, &bufferSize);
    }

    if (ret == NO_ERROR) {
        // Iterate through the adapter list and print interface names and IPs
        for (PIP_ADAPTER_ADDRESSES adapter = adapterAddresses; adapter != nullptr; adapter = adapter->Next) {
            cout << "Interface: " << adapter->AdapterName;
            if (adapter->FriendlyName) {
                wcout << " (" << adapter->FriendlyName << ")";
            }
            cout << endl;

            // Iterate through unicast addresses
            for (PIP_ADAPTER_UNICAST_ADDRESS ua = adapter->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
                char ip[INET6_ADDRSTRLEN] = { 0 };
                // Check address family and convert to string 
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ip, sizeof(ip));
                    cout << "  IPv4: " << ip << endl;
                    // Check for IPv6 addresses
                }
                else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                    sockaddr_in6* sa_in6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET6, &(sa_in6->sin6_addr), ip, sizeof(ip));
                    cout << "  IPv6: " << ip << endl;
                }
            }
        }
    }
    else {
        cout << "GetAdaptersAddresses failed with error: " << ret << endl;
    }
    WSACleanup();
#else
    cout << "Interface listing is not implemented for this platform." << endl;
#endif
}

// these are temporary and meant to be placeholder
void list_rules() {
    cout << "Current Monitoring Rules:" << endl;
    cout << "1. Rule Name: High Unique SCID/DCID Count" << endl;
    cout << "   Description: Alerts when the number of unique Source Connection IDs (SCIDs) or Destination Connection IDs (DCIDs) exceeds a specified threshold within a monitoring interval." << endl;
    cout << "   Parameters:" << endl;
    cout << "Initial Percentage Threshold : 70" << endl;
    cout << "Unique SCID Threshold : 0.8" << endl;
    cout << "Unique DCID Threshold : 0.8" << endl;
    cout << "Monitoring Interval (seconds) : 60" << endl;
}

// this is also a placeholder function to update the rules
void update_rules() {
    vector<string> new_rules;
    cout << "Enter new rules (type 'done' to finish):" << endl;
    string rule;
    while (true) {
        getline(cin, rule);
        if (rule == "done") {
            break;
        }
        if (!rule.empty()) {
            new_rules.push_back(rule);
        }
    }
    cout << "Updated Rules:" << endl;
    for (const auto& r : new_rules) {
        cout << r << endl;
    }
}

// Function to monitor network traffic based on specified interfaces and rules
void monitor(const vector<string>& ifaces, const string& rule) {

    cout << "Starting monitoring on interfaces: ";
    // Print specified interfaces
    for (const auto& iface : ifaces) {
        cout << iface << " ";
    }
    cout << "with rule: " << rule << endl;

    cout << "Alerts: \n" << endl;
    ifstream infile(json_log);

    // Check if the log file is opened or not
    if (!infile.is_open()) {
        cout << "Could not open log file: " << json_log << endl;
        return;
    }

    // Parse each line in the JSON log file
    simdjson::dom::parser parser;
    string line;
    while (getline(infile, line)) {
        try {
            auto doc = parser.parse(line);
            cout << "Timestamp: " << string(doc["@timestamp"]) << endl;
            cout << "Interface: " << string(doc["network"]["interface"]) << endl;
            cout << "Source IP: " << string(doc["network"]["source"]) << endl;
            cout << "Destination IP: " << string(doc["network"]["destination"]) << endl;
            cout << "Packets: " << int64_t(doc["metrics"]["packet_count"]) << endl;
            cout << "Connections: " << int64_t(doc["metrics"]["connection_count"]) << endl;
            cout << "Handshakes: " << int64_t(doc["metrics"]["handshake_count"]) << endl;
            cout << "Malformed: " << int64_t(doc["metrics"]["malformed_count"]) << endl;
            cout << "-----------------------------" << endl;
        }
        catch (const simdjson::simdjson_error& e) {
            cout << "Error parsing log entry: " << e.what() << endl;
        }
    }
}

// Main function to parse command-line arguments and execute commands
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return 0;
    }

    // Parse command from arguments starting from the second position
    // this is because the first position is the program name
    string cmd = argv[1];

    if (cmd == "--help") {
        print_help();
    }
    else if (cmd == "list-interfaces") {
        list_interfaces();
    }
    else if (cmd == "list-rules") {
        list_rules();
    }
    else if (cmd == "update") {
        if (argc >= 3 && (string(argv[2]) == "-r" || string(argv[2]) == "--rules")) {
            update_rules();
        }
        else {
            cout << "Invalid arguments for update. Use --help for usage." << endl;
        }
        // Monitor command parsing
    }
    else if (cmd == "monitor") {
        vector<string> ifaces;
        string rule;
        for (int i = 2; i < argc; ++i) {
            string arg = argv[i];
            if ((arg == "-i" || arg == "--interfaces") && i + 1 < argc) {
                // Collect all interfaces until next option or end
                while (i + 1 < argc && argv[i + 1][0] != '-') {
                    ifaces.push_back(argv[++i]);
                }
            }
            else if ((arg == "-r" || arg == "--rules") && i + 1 < argc) {
                rule = argv[++i];
            }
        }
        if (!ifaces.empty() && !rule.empty()) {
            monitor(ifaces, rule);
        }
        else {
            cout << "Missing interface or rule for monitor. Use --help for commands." << endl;
        }
    }
    else {
        cout << "Unknown command. Use --help for list of commands." << endl;
    }

    return 0;
}
