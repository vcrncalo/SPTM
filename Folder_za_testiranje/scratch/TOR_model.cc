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

#include "TOR_packet.h"

NS_LOG_COMPONENT_DEFINE("TORNetworkExample");

class TORMonitor {
public:
    static void PrintNodeStats(Ptr<Node> node, std::string description) {
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        if (ipv4) {
            NS_LOG_INFO("Node " << node->GetId() << " (" << description << ") Statistics:");
            for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++) {
                NS_LOG_INFO("  Interface " << i << ":");
                NS_LOG_INFO("    IP: " << ipv4->GetAddress(i, 0).GetLocal());
                NS_LOG_INFO("    Role: " << description);
            }
        }
    }
};

// Enhanced encryption with multiple layers and key rotation using OpenSSL EVP
class TOREncryption {
private:
    static std::vector<std::string> keys;

    static std::string GenerateKey(int length = 32) {
        std::vector<unsigned char> key(length);
        RAND_bytes(key.data(), length);
        return std::string(reinterpret_cast<char*>(key.data()), length);
    }

public:
    static void InitializeKeys(int numLayers) {
        keys.clear();
        for (int i = 0; i < numLayers; ++i) {
            keys.push_back(GenerateKey());
        }
    }

    static std::string EncryptLayer(const std::string &data, int layer) {
        if (layer < 0 || layer >= static_cast<int>(keys.size())) {
            throw std::runtime_error("Invalid layer");
        }

        std::string encrypted;

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if(!ctx) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }

        if(1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, (const unsigned char*)keys[layer].c_str(), (const unsigned char*)keys[layer].c_str())) {
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[data.length() + EVP_MAX_BLOCK_LENGTH]);
        int ciphertext_len;
        int len;

        if(1 != EVP_EncryptUpdate(ctx.get(), ciphertext.get(), &len, (const unsigned char*)data.c_str(), data.length())) {
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        ciphertext_len = len;

        if(1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext.get() + len, &len)) {
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }
        ciphertext_len += len;

        encrypted = std::string(reinterpret_cast<char*>(ciphertext.get()), ciphertext_len);

        return encrypted;
    }

    static std::string DecryptLayer(const std::string &data, int layer) {
        if (layer < 0 || layer >= static_cast<int>(keys.size())) {
            throw std::runtime_error("Invalid layer");
        }

        std::string decrypted;

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if(!ctx) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }

        if(1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, (const unsigned char*)keys[layer].c_str(), (const unsigned char*)keys[layer].c_str())) {
            throw std::runtime_error("EVP_DecryptInit_ex failed");
        }

        std::unique_ptr<unsigned char[]> plaintext(new unsigned char[data.length()]);
        int plaintext_len;
        int len;

        if(1 != EVP_DecryptUpdate(ctx.get(), plaintext.get(), &len, (const unsigned char*)data.c_str(), data.length())) {
            throw std::runtime_error("EVP_DecryptUpdate failed");
        }
        plaintext_len = len;

        if(1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.get() + len, &len)) {
            throw std::runtime_error("EVP_DecryptFinal_ex failed");
        }
        plaintext_len += len;

        decrypted = std::string(reinterpret_cast<char*>(plaintext.get()), plaintext_len);

        return decrypted;
    }
};

std::vector<std::string> TOREncryption::keys;

void PrintPacketHeader(const TORPacket& packet) {
    NS_LOG_INFO("Packet Header Data:");
    NS_LOG_INFO("  Sequence Number: " << packet.sequenceNumber);
    NS_LOG_INFO("  Encryption Layer: " << packet.encryptionLayer);
    NS_LOG_INFO("  Timestamp: " << packet.timestamp);
    NS_LOG_INFO("  Hop Count: " << packet.hopCount);
    NS_LOG_INFO("  Source Node: " << packet.sourceNode);
    NS_LOG_INFO("  Destination Node: " << packet.destinationNode);
    NS_LOG_INFO("  Circuit ID: " << packet.circuitId);
    NS_LOG_INFO("  Is Control: " << (packet.isControl ? "Yes" : "No"));
    NS_LOG_INFO("  Protocol: " << packet.protocol);
}

void TORPacket::EncryptPacket(const std::string& key) {
    data = TOREncryption::EncryptLayer(data, encryptionLayer);
}

void TORPacket::DecryptPacket(const std::string& key) {
    data = TOREncryption::DecryptLayer(data, encryptionLayer);
}

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
    // Configure client applications with encryption
    OnOffHelper clientHelper("ns3::TcpSocketFactory",
                           InetSocketAddress(interfaces6.GetAddress(1), port));
    clientHelper.SetAttribute("DataRate", StringValue("5Mbps"));
    clientHelper.SetAttribute("PacketSize", UintegerValue(1000));
    clientHelper.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=1]"));
    clientHelper.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.1]"));

    ApplicationContainer clientApps;
    Ptr<Node> clientNode = nodes.Get(0);
    clientApps.Add(clientHelper.Install(clientNode));

    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));

    ApplicationContainer serverApps;
    Ptr<Node> destinationNode = nodes.Get(6);
    serverApps.Add(sinkHelper.Install(destinationNode)); // Only destination receives

    clientApps.Start(Seconds(1.0));
    const double CLIENT_STOP_TIME = 9.0;
    clientApps.Stop(Seconds(CLIENT_STOP_TIME));
    const double SERVER_START_TIME = 0.0;
    serverApps.Start(Seconds(SERVER_START_TIME));
    const double SERVER_STOP_TIME = 10.0;
    serverApps.Stop(Seconds(SERVER_STOP_TIME));

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
        NS_LOG_INFO(""); // Add a new line between nodes
    }

    anim.EnablePacketMetadata(true);
    // anim.EnableIpv4RouteTracking("tor-routes.xml", Seconds(0), Seconds(22)); // Removed route tracking

    const double SIMULATION_STOP_TIME = 10.0;
    Simulator::Stop(Seconds(SIMULATION_STOP_TIME));
    // Initialize encryption keys
    TOREncryption::InitializeKeys(6);

    // Simulate packet transmission and encryption
    Simulator::Schedule(Seconds(2.0), [&](){
        // Create a TOR packet
        TORPacket packet;
        packet.sequenceNumber = 1;
        packet.data = "This is a test message";
        packet.timestamp = Simulator::Now().GetSeconds();
        packet.hopCount = 0;
        packet.sourceNode = "Client";
        packet.destinationNode = "Destination";
        packet.circuitId = 123;
        packet.isControl = false;
        packet.protocol = 6; // TCP

        NS_LOG_INFO("================ Packet Data ==================");
        NS_LOG_INFO("Original Packet Data: " << packet.data);

        // Encrypt at client
        packet.encryptionLayer = 0;
        packet.EncryptPacket("key1");
        NS_LOG_INFO("Packet Data after Client Encryption: " << packet.data);

        // Simulate packet forwarding through the TOR network
        // Decrypt at Entry Node
        packet.encryptionLayer = 0;
        packet.DecryptPacket("key1");
        NS_LOG_INFO("Packet Data after Entry Decryption: " << packet.data);

        // Encrypt at Entry Node
        packet.encryptionLayer = 1;
        packet.EncryptPacket("key2");
        NS_LOG_INFO("Packet Data after Entry Encryption: " << packet.data);

        // Decrypt at Relay 1
        packet.encryptionLayer = 1;
        packet.DecryptPacket("key2");
        NS_LOG_INFO("Packet Data after Relay 1 Decryption: " << packet.data);

        // Encrypt at Relay 1
        packet.encryptionLayer = 2;
        packet.EncryptPacket("key3");
        NS_LOG_INFO("Packet Data after Relay 1 Encryption: " << packet.data);

        // Decrypt at Relay 2
        packet.encryptionLayer = 2;
        packet.DecryptPacket("key3");
        NS_LOG_INFO("Packet Data after Relay 2 Decryption: " << packet.data);

        // Encrypt at Relay 2
        packet.encryptionLayer = 3;
        packet.EncryptPacket("key4");
        NS_LOG_INFO("Packet Data after Relay 2 Encryption: " << packet.data);

        // Decrypt at Relay 3
        packet.encryptionLayer = 3;
        packet.DecryptPacket("key4");
        NS_LOG_INFO("Packet Data after Relay 3 Decryption: " << packet.data);

        // Encrypt at Relay 3
        packet.encryptionLayer = 4;
        packet.EncryptPacket("key5");
        NS_LOG_INFO("Packet Data after Relay 3 Encryption: " << packet.data);

        // Decrypt at Exit Node
        packet.encryptionLayer = 4;
        packet.DecryptPacket("key5");
        NS_LOG_INFO("Packet Data after Exit Decryption: " << packet.data);

        // Encrypt at Exit Node
        packet.encryptionLayer = 5;
        packet.EncryptPacket("key6");
        NS_LOG_INFO("Packet Data after Exit Encryption: " << packet.data);

        // Decrypt at Destination
        packet.encryptionLayer = 5;
        packet.DecryptPacket("key6");
        NS_LOG_INFO("Packet Data after Destination Decryption: " << packet.data);
        NS_LOG_INFO("");
        PrintPacketHeader(packet);
        NS_LOG_INFO("================================================");
    });

    Simulator::Run();

    // Print detailed statistics
    flowMonitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();

    NS_LOG_INFO("================ TOR NETWORK STATISTICS ================");
    NS_LOG_INFO("");
    NS_LOG_INFO("Verifying Flow Monitoring Configuration:");
    NS_LOG_INFO("Flow Monitor: " << flowMonitor);
    NS_LOG_INFO("Flow Classifier: " << classifier);
    NS_LOG_INFO("Flow Stats: " << stats.size());
    NS_LOG_INFO("");

    // Print flow statistics
    for (auto& stat : stats) {
        NS_LOG_INFO("Flow ID: " << stat.first);
        auto flow = classifier->FindFlow(stat.first);
        NS_LOG_INFO("  Source Address: " << flow.sourceAddress);
        NS_LOG_INFO("  Destination Address: " << flow.destinationAddress);
        NS_LOG_INFO("  Protocol: " << (flow.protocol == 6 ? "TCP" : (flow.protocol == 17 ? "UDP" : "Unknown")));
        NS_LOG_INFO("  Packets: " << stat.second.txPackets + stat.second.rxPackets);
        NS_LOG_INFO("  Transmitted Packets: " << stat.second.txPackets);
        NS_LOG_INFO("  Received Packets: " << stat.second.rxPackets);
        NS_LOG_INFO("  Bytes: " << stat.second.txBytes + stat.second.rxBytes);
        NS_LOG_INFO("  Transmitted Bytes: " << stat.second.txBytes);
        NS_LOG_INFO("  Received Bytes: " << stat.second.rxBytes);
        NS_LOG_INFO("  Delay: " << stat.second.delaySum.GetSeconds() / (stat.second.txPackets + stat.second.rxPackets) << " seconds");
        NS_LOG_INFO("  Lost Packets: " << stat.second.lostPackets);
        NS_LOG_INFO("");
    }

    // Calculate and print overall network statistics
uint64_t totalTxBytes = 0, totalRxBytes = 0;
uint32_t totalTxPackets = 0, totalRxPackets = 0, totalLostPackets = 0;
double totalDelay = 0;

for (auto& stat : stats) {
    totalTxBytes += stat.second.txBytes; // Bytes transmitted by all sources
    totalRxBytes += stat.second.rxBytes; // Bytes received by all destinations
    totalTxPackets += stat.second.txPackets; // Packets transmitted by all sources
    totalRxPackets += stat.second.rxPackets; // Packets received by all destinations
    totalLostPackets += stat.second.lostPackets; // Total lost packets across all flows
    totalDelay += stat.second.delaySum.GetSeconds(); // Sum of delays for all received packets
}

NS_LOG_INFO("Overall Network Statistics:");
NS_LOG_INFO("Total Transmitted Packets: " << totalTxPackets); // Total packets transmitted by all source nodes
NS_LOG_INFO("Total Received Packets: " << totalRxPackets);   // Total packets received by all destination nodes
NS_LOG_INFO("Total Lost Packets: " << totalLostPackets);
NS_LOG_INFO("Average Delay: " << totalDelay/totalRxPackets << " seconds");
NS_LOG_INFO("Packet Delivery Ratio: " << (double)totalRxPackets/totalTxPackets * 100 << "%");
    NS_LOG_INFO("================ Overall Network Statistics ==================");

    Simulator::Destroy();
    return 0;
}
