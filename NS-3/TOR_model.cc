#include <string>
#include <sstream>
#include <iomanip>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/mobility-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/stats-module.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <memory>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TORNetworkExample");

// Enhanced packet structure for TOR with additional fields
struct TORPacket {
    uint32_t sequenceNumber;
    std::string data;
    uint32_t encryptionLayer;
    double timestamp;
    uint32_t hopCount;
    std::string sourceNode;
    std::string destinationNode;
    uint32_t circuitId;
    bool isControl;
    std::vector<std::string> encryptionLayers; // Store encryption at each hop
};

class TORMonitor {
public:
    static void PrintNodeStats(Ptr<Node> node, std::string description) {
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        if (ipv4) {
            std::cout << "\nNode " << node->GetId() << " (" << description << ") Statistics:" << std::endl;
            for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++) {
                std::cout << "  Interface " << i << ":" << std::endl;
                std::cout << "    IP: " << ipv4->GetAddress(i, 0).GetLocal() << std::endl;
                std::cout << "    Role: " << description << std::endl;
            }
        }
    }
};

// Enhanced encryption with multiple layers and key rotation using OpenSSL EVP
class TOREncryption {
private:
    static std::string GenerateKey(int length = 32) {
        std::vector<unsigned char> key(length);
        RAND_bytes(key.data(), length);
        return std::string(reinterpret_cast<char*>(key.data()), length);
    }

public:
    static std::string EncryptLayer(const std::string &data, int layer) {
        std::string key = GenerateKey();
        std::string encrypted;
        
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(!ctx) {
            return "";
        }
        
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_ptr(ctx, EVP_CIPHER_CTX_free);


        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)key.c_str())) {
            return "";
        }

        unsigned char *ciphertext = (unsigned char*)malloc(data.length() + EVP_MAX_BLOCK_LENGTH);
        if(!ciphertext) {
            return "";
        }
        std::unique_ptr<unsigned char, decltype(&free)> ciphertext_ptr(ciphertext, free);
        int ciphertext_len;
        int len;


        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)data.c_str(), data.length())) {
            return "";
        }
        ciphertext_len = len;


        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
            return "";
        }
        ciphertext_len += len;

        encrypted = std::string(reinterpret_cast<char*>(ciphertext), ciphertext_len);

        return encrypted;
    }

    static std::string DecryptLayer(const std::string &data, int layer) {
        std::string key = GenerateKey();
        std::string decrypted;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(!ctx) {
            return "";
        }
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_ptr(ctx, EVP_CIPHER_CTX_free);


        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)key.c_str())) {
            return "";
        }

        unsigned char *plaintext = (unsigned char*)malloc(data.length());
        if(!plaintext) {
            return "";
        }
        std::unique_ptr<unsigned char, decltype(&free)> plaintext_ptr(plaintext, free);
        int plaintext_len;
        int len;


        if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, (const unsigned char*)data.c_str(), data.length())) {
            return "";
        }
        plaintext_len = len;


        if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
            return "";
        }
        plaintext_len += len;

        decrypted = std::string(reinterpret_cast<char*>(plaintext), plaintext_len);

        return decrypted;
    }
};

int main(int argc, char *argv[]) {
    LogComponentEnable("TORNetworkExample", LOG_LEVEL_INFO);
    
    CommandLine cmd;
    cmd.Parse(argc, argv);

    NodeContainer nodes;
    nodes.Create(7); // 7 nodes: Client, Entry, 3 Relays, Exit, Destination

    // Set up node positions
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue(0.0),
                                 "MinY", DoubleValue(0.0),
                                 "DeltaX", DoubleValue(20.0),
                                 "DeltaY", DoubleValue(20.0),
                                 "GridWidth", UintegerValue(4),
                                 "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("1ms"));
    p2p.SetQueue("ns3::DropTailQueue<Packet>",
                 "MaxSize", QueueSizeValue(QueueSize("1000p"))); // Limit queue size

    // Create TOR circuit connections
    NetDeviceContainer devices2 = p2p.Install(nodes.Get(0), nodes.Get(1)); // Client -> Entry
    NetDeviceContainer devices3 = p2p.Install(nodes.Get(1), nodes.Get(2)); // Entry -> Relay1
    NetDeviceContainer devices4 = p2p.Install(nodes.Get(2), nodes.Get(3)); // Relay1 -> Relay2
    NetDeviceContainer devices5 = p2p.Install(nodes.Get(3), nodes.Get(4)); // Relay2 -> Relay3
    NetDeviceContainer devices6 = p2p.Install(nodes.Get(4), nodes.Get(5)); // Relay3 -> Exit
    NetDeviceContainer devices7 = p2p.Install(nodes.Get(5), nodes.Get(6)); // Exit -> Destination

    InternetStackHelper stack;
    stack.Install(nodes);

    // Assign IP addresses
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces1 = address.Assign(devices2);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces2 = address.Assign(devices3);

    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces3 = address.Assign(devices4);

    address.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces4 = address.Assign(devices5);

    address.SetBase("10.1.5.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces5 = address.Assign(devices6);

    address.SetBase("10.1.6.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces6 = address.Assign(devices7);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Set up flow monitoring
    Ptr<FlowMonitor> flowMonitor;
    FlowMonitorHelper flowHelper;
    flowMonitor = flowHelper.InstallAll();

    uint16_t port = 9001;

    // Configure client applications with encryption
    OnOffHelper clientHelper("ns3::TcpSocketFactory", 
                           InetSocketAddress(interfaces6.GetAddress(1), port));
    clientHelper.SetAttribute("DataRate", StringValue("5Mbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(1000)); // Smaller packets
    clientHelper.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=1]"));
    clientHelper.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.1]"));
    
    ApplicationContainer clientApps;
    clientApps.Add(clientHelper.Install(nodes.Get(0)));

    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
    
    ApplicationContainer serverApps;
    serverApps.Add(sinkHelper.Install(nodes.Get(6))); // Only destination receives

    clientApps.Start(Seconds(1.0));
    clientApps.Stop(Seconds(9.0));
    serverApps.Start(Seconds(0.0));
    serverApps.Stop(Seconds(10.0));

    // Visualization setup with limited trace file size
    AnimationInterface anim("tor-network-visualization.xml");
    anim.SetMaxPktsPerTraceFile(1000000); // Limit trace file size
    
    // Node roles and colors
    std::vector<std::pair<std::string, std::vector<uint32_t>>> nodeRoles = {
        {"TOR Client", {255, 0, 0}},
        {"Entry Guard", {0, 255, 0}},
        {"Relay 1", {0, 0, 255}},
        {"Relay 2", {128, 0, 128}},
        {"Relay 3", {255, 165, 0}},
        {"Exit Node", {0, 255, 255}},
        {"Destination", {255, 255, 0}}
    };

    // Set node colors and descriptions
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        auto& role = nodeRoles[i];
        anim.UpdateNodeColor(nodes.Get(i), role.second[0], role.second[1], role.second[2]);
        anim.UpdateNodeDescription(nodes.Get(i), role.first);
        TORMonitor::PrintNodeStats(nodes.Get(i), role.first);
    }

    anim.EnablePacketMetadata(true);
    // anim.EnableIpv4RouteTracking("tor-routes.xml", Seconds(0), Seconds(22)); // Removed route tracking

    Simulator::Stop(Seconds(10.0));
    Simulator::Run();

    // Print detailed statistics
    flowMonitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();

    std::cout << "\n================ TOR NETWORK STATISTICS ================\n" << std::endl;
    
    // Print per-node statistics
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        std::cout << "\nNode " << i << " (" << nodeRoles[i].first << "):" << std::endl;
        TORMonitor::PrintNodeStats(nodes.Get(i), nodeRoles[i].first);
    }

    // Calculate and print overall network statistics
    uint64_t totalTxBytes = 0, totalRxBytes = 0;
    uint32_t totalTxPackets = 0, totalRxPackets = 0;
    double totalDelay = 0;

    for (auto& stat : stats) {
        totalTxBytes += stat.second.txBytes;
        totalRxBytes += stat.second.rxBytes;
        totalTxPackets += stat.second.txPackets;
        totalRxPackets += stat.second.rxPackets;
        totalDelay += stat.second.delaySum.GetSeconds();
    }

    std::cout << "\nOverall Network Statistics:" << std::endl;
    std::cout << "Total Transmitted Packets: " << totalTxPackets << std::endl;
    std::cout << "Total Received Packets: " << totalRxPackets << std::endl;
    std::cout << "Average Delay: " << totalDelay/totalRxPackets << " seconds" << std::endl;
    std::cout << "Packet Delivery Ratio: " << (double)totalRxPackets/totalTxPackets * 100 << "%" << std::endl;

    Simulator::Destroy();
    return 0;
}
