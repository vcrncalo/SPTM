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
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <vector>
#include <memory>
#include <map>

using namespace ns3;

#include "TOR_packet.h"

NS_LOG_COMPONENT_DEFINE("TORNetworkExample");

void initialize_openssl() {
    // Initialize OpenSSL
    OPENSSL_no_config();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    // Add detailed logging for OpenSSL initialization
    NS_LOG_INFO("OpenSSL initialized successfully.");
}

class TORMonitor {
public:
    static void PrintNodeStats(Ptr<Node> node, std::string description) {
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        if (ipv4) {
            NS_LOG_INFO("Node " << node->GetId() << " (" << description << ") Statistics:");
            for (uint32_t i = 0; i < ipv4->GetNInterfaces(); i++) {
                NS_LOG_INFO("  Interface " << i << ":");
                Ptr<NetDevice> netDevice = node->GetDevice(i);
                for (uint32_t j = 0; j < ipv4->GetNAddresses(i); ++j) {
                    Ipv4InterfaceAddress addr = ipv4->GetAddress(i, j);
                    NS_LOG_INFO("    IP: " << addr.GetLocal());
                }
            }
        }
    }
};

class TORCircuit {
public:
    std::vector<uint32_t> path;
    std::vector<std::string> keys;
    uint32_t circuitId;

    TORCircuit(const std::vector<uint32_t>& path, const std::vector<std::string>& keys, uint32_t circuitId)
        : path(path), keys(keys), circuitId(circuitId) {}
};

// Enhanced encryption with multiple layers and key rotation using OpenSSL EVP
class TOREncryption {
public:
    static std::vector<std::string> keys;

    static void InitializeKeys(int numLayers) {
        keys.clear();
        for (int i = 0; i < numLayers; ++i) {
            keys.push_back(GenerateKey());
        }
    }

    static std::string GenerateKey(int length = 32) {
        std::vector<unsigned char> key(length);
        RAND_bytes(key.data(), length);
        return std::string(reinterpret_cast<char*>(key.data()), length);
    }

    static std::string EncryptLayer(const std::string &data, int layer) {
        if (layer < 0 || layer >= static_cast<int>(keys.size())) {
            throw std::runtime_error("Invalid layer");
        }

        NS_LOG_INFO("EncryptLayer input data (hex): ");
        std::stringstream ss;
        for (char c : data) {
            ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
        }
        NS_LOG_INFO(ss.str());
        NS_LOG_INFO("EncryptLayer key (hex): ");
        std::stringstream key_ss;
        for (char c : keys[layer]) {
            key_ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
        }
        NS_LOG_INFO(key_ss.str());

        std::string encrypted;

        auto ctx = CreateOpenSSLContext(layer, true);

        std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[data.length() + EVP_MAX_BLOCK_LENGTH]);
        int ciphertext_len;
        int len;

        if(1 != EVP_EncryptUpdate(ctx.get(), ciphertext.get(), &len, (const unsigned char*)data.c_str(), data.length())) {
            throw std::runtime_error("TOREncryption::EncryptLayer: EVP_EncryptUpdate failed");
        }
        ciphertext_len = len;

        if(1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext.get() + len, &len)) {
            throw std::runtime_error("TOREncryption::EncryptFinal_ex failed");
        }
        ciphertext_len += len;

        encrypted = std::string(reinterpret_cast<char*>(ciphertext.get()), ciphertext_len);

        NS_LOG_INFO("EncryptLayer output data (hex): ");
        std::stringstream ss_out;
        for (char c : encrypted) {
            ss_out << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
        }
        NS_LOG_INFO(ss_out.str());

        return encrypted;
    }

    static std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> CreateOpenSSLContext(int layer, bool encrypt) {
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if(!ctx) {
            throw std::runtime_error("CreateOpenSSLContext: EVP_CIPHER_CTX_new failed");
        }

        const unsigned char* key = (const unsigned char*)keys[layer].c_str();
        if (encrypt) {
            if(1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, key)) {
                throw std::runtime_error("CreateOpenSSLContext: EVP_EncryptInit_ex failed");
            }
        } else {
            if(1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key, key)) {
                throw std::runtime_error("CreateOpenSSLContext: EVP_DecryptInit_ex failed");
            }
        }
        return ctx;
    }

    static std::string DecryptLayer(const std::string &data, int layer) {
        if (layer < 0 || layer >= static_cast<int>(keys.size())) {
            throw std::runtime_error("Invalid layer");
        }

        NS_LOG_INFO("DecryptLayer input data (hex): ");
        std::stringstream ss;
        for (char c : data) {
            ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
        }
        NS_LOG_INFO(ss.str());
        NS_LOG_INFO("DecryptLayer key (hex): ");
        std::stringstream key_ss;
        for (char c : keys[layer]) {
            key_ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
        }
        NS_LOG_INFO(key_ss.str());

        std::string decrypted;

        auto ctx = CreateOpenSSLContext(layer, false);

        std::unique_ptr<unsigned char[]> plaintext(new unsigned char[data.length()]);
        int plaintext_len;
        int len;

        if(1 != EVP_DecryptUpdate(ctx.get(), plaintext.get(), &len, (const unsigned char*)data.c_str(), data.length())) {
            throw std::runtime_error("TOREncryption::DecryptLayer: EVP_DecryptUpdate failed");
        }
        plaintext_len = len;

        if(1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.get() + len, &len)) {
            throw std::runtime_error("TOREncryption::DecryptFinal_ex failed");
        }
        plaintext_len += len;

        decrypted = std::string(reinterpret_cast<char*>(plaintext.get()), plaintext_len);

        NS_LOG_INFO("DecryptLayer output data (hex): ");
        std::stringstream ss_out;
        for (char c : decrypted) {
            ss_out << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
        }
        NS_LOG_INFO(ss_out.str());

        return decrypted;
    }
};

std::vector<std::string> TOREncryption::keys;

std::map<uint32_t, TORCircuit> circuits;

void SendPacket(Ptr<Node> fromNode, Ptr<Node> toNode, TORPacket packet, uint16_t protocol) {
    // Create a new packet
    Ptr<Packet> p = Create<Packet>((uint8_t*)&packet, sizeof(packet));

    // Get the IP address of the destination node
    Ptr<Ipv4> ipv4 = toNode->GetObject<Ipv4>();
    Ipv4Address destAddr = ipv4->GetAddress(1, 0).GetLocal();

    // Create a socket for sending the packet
    TypeId tid = TypeId::LookupByName("ns3::TcpSocketFactory");
    if (protocol == 17) {
        tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    }
    Ptr<Socket> socket = Socket::CreateSocket(fromNode, tid);

    // Connect the socket to the destination address and port
    Ptr<Ipv4> fromIpv4 = fromNode->GetObject<Ipv4>();
    if (protocol == 6) {
        socket->Connect(InetSocketAddress(destAddr, 9001));
    } else if (protocol == 17) {
        socket->Connect(InetSocketAddress(destAddr, 9002));
    }

    // Send the packet
    socket->Send(p);
}

void PrintPacketHeader(const TORPacket& packet) {
    NS_LOG_INFO("================ PACKET DATA ==================");
    NS_LOG_INFO("Packet Header Data:");
    NS_LOG_INFO("  Sequence Number: " << packet.sequenceNumber);
    NS_LOG_INFO("  Current Layer: " << packet.currentLayer);
    NS_LOG_INFO("  Timestamp: " << packet.timestamp);
    NS_LOG_INFO("  Hop Count: " << packet.hopCount);
    NS_LOG_INFO("  Source Node: " << packet.sourceNode);
    NS_LOG_INFO("  Destination Node: " << packet.destinationNode);
    NS_LOG_INFO("  Circuit ID: " << packet.circuitId);
    NS_LOG_INFO("  Is Control: " << (packet.isControl ? "Yes" : "No"));
    NS_LOG_INFO("  Route: ");
    for (uint32_t nodeId : packet.route) {
        NS_LOG_INFO("    Node ID: " << nodeId);
    }
    NS_LOG_INFO("  Protocol: " << packet.protocol);
}

void TORPacket::EncryptPacket(const std::string& key) {
    data = TOREncryption::EncryptLayer(data, currentLayer);
}

void TORPacket::DecryptPacket(const std::string& key) {
    data = TOREncryption::DecryptLayer(data, currentLayer);
    if (!VerifyChecksum()) {
        throw std::runtime_error("Packet checksum verification failed");
    }
}

void TORPacket::CalculateChecksum() {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("TORPacket::CalculateChecksum: EVP_MD_CTX_new failed");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::CalculateChecksum: EVP_DigestInit_ex failed");
    }

    if (1 != EVP_DigestUpdate(mdctx, originalData.c_str(), originalData.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::CalculateChecksum: EVP_DigestUpdate failed");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::CalculateChecksum: EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(mdctx);
    checksum = std::string(reinterpret_cast<char*>(hash), lengthOfHash);
    NS_LOG_INFO("Checksum calculated: " << checksum);
}

bool TORPacket::VerifyChecksum() {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("TORPacket::VerifyChecksum: EVP_MD_CTX_new failed");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::VerifyChecksum: EVP_DigestInit_ex failed");
    }

    if (1 != EVP_DigestUpdate(mdctx, originalData.c_str(), originalData.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::VerifyChecksum: EVP_DigestUpdate failed");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::VerifyChecksum: EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(mdctx);
    std::string calculatedChecksum = std::string(reinterpret_cast<char*>(hash), lengthOfHash);
    NS_LOG_INFO("Checksum verification result: " << (checksum == calculatedChecksum ? "Success" : "Failed") << " (calculated: " << calculatedChecksum << ", original: " << checksum << ")");
    return checksum == calculatedChecksum;
}

bool ExitNodePolicy(const TORPacket& packet, uint32_t destinationNodeId) {
    // Example policy: Only allow packets to the destination node (node ID 6)
    if (packet.destinationNode == "Destination" && destinationNodeId == 6) {
        return true;
    }
    return false;
}

void ProcessHop(TORPacket& packet, size_t layer, const std::vector<std::string>& keys, uint32_t nodeId) {
    if (layer >= keys.size()) {
        NS_LOG_ERROR("Invalid layer: " << layer);
        return;
    }
    packet.DecryptPacket(keys[layer]);
    NS_LOG_INFO("=========================================");
    NS_LOG_INFO("");
    NS_LOG_INFO("Packet Data after Decryption at Layer " << layer << ": " << packet.data);
    NS_LOG_INFO("");
    NS_LOG_INFO("=========================================");

    packet.hopCount++;
    if (static_cast<size_t>(layer + 1) < keys.size()) {
        packet.currentLayer = layer + 1;
        packet.EncryptPacket(keys[layer + 1]);
    	NS_LOG_INFO("=========================================");
    	NS_LOG_INFO("");
        NS_LOG_INFO("Packet Data after Encryption at Layer " << layer + 1 << ": " << packet.data);
    	NS_LOG_INFO("");
    	NS_LOG_INFO("=========================================");
    }
    packet.route.push_back(nodeId);

    // Forward the packet to the next node in the path
    if (static_cast<size_t>(layer + 1) < keys.size()) {
        auto circuit_it = circuits.find(packet.circuitId);
        if (circuit_it == circuits.end()) {
            NS_LOG_ERROR("Circuit not found: " << packet.circuitId);
            return;
        }
        const TORCircuit& circuit = circuit_it->second;
         if (static_cast<size_t>(layer + 1) >= circuit.path.size()) {
            NS_LOG_ERROR("Path index out of bounds: " << layer + 1);
            return;
        }
        uint32_t nextNodeId = circuit.path[layer + 1];
        Ptr<Node> fromNode = NodeList::GetNode(nodeId);
        Ptr<Node> toNode = NodeList::GetNode(nextNodeId);
        SendPacket(fromNode, toNode, packet, packet.protocol);
    } else {
        NS_LOG_INFO("Packet reached end of circuit path.");
    }
}

TORCircuit CreateCircuit(uint32_t circuitId, const std::vector<uint32_t>& path, int numLayers) {
    std::vector<std::string> keys;
    for (int i = 0; i < numLayers; ++i) {
        keys.push_back(TOREncryption::GenerateKey());
    }
    NS_LOG_INFO("Circuit created with ID: " << circuitId);
    NS_LOG_INFO("  Path: ");
    for (uint32_t nodeId : path) {
        NS_LOG_INFO("    Node ID: " << nodeId);
    }
    return TORCircuit(path, keys, circuitId);
}

int main(int argc, char *argv[]) {
    initialize_openssl();
    LogComponentEnable("TORNetworkExample", LOG_LEVEL_INFO);

    CommandLine cmd;
    std::string initialData = "This is a test message";
    double simulationTime = 10.0;
    std::string dataRate = "5Mbps";
    uint32_t packetSize = 1000;
    std::string queueSize = "1000p";
    double onTimeMean = 1.0;
    double offTimeMean = 0.1;
    uint16_t port = 9001;

    cmd.AddValue("initialData", "Initial data for the packet", initialData);
    cmd.AddValue("simulationTime", "Simulation time in seconds", simulationTime);
    cmd.AddValue("dataRate", "Data rate for the client application", dataRate);
    cmd.AddValue("packetSize", "Packet size for the client application", packetSize);
    cmd.AddValue("queueSize", "Queue size for the point-to-point links", queueSize);
    cmd.AddValue("onTimeMean", "Mean on time for the client application", onTimeMean);
    cmd.AddValue("offTimeMean", "Mean off time for the client application", offTimeMean);
    cmd.AddValue("port", "Port number for the client and server applications", port);
    cmd.Parse(argc, argv);

    NodeContainer nodes;
    nodes.Create(7);

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
                 "MaxSize", QueueSizeValue(QueueSize(queueSize))); // Limit queue size

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

    // Configure client applications with encryption
    OnOffHelper clientHelper("ns3::TcpSocketFactory",
                           InetSocketAddress(interfaces6.GetAddress(1), port));
    clientHelper.SetAttribute("DataRate", StringValue(dataRate));
    clientHelper.SetAttribute("PacketSize", UintegerValue(packetSize));
    clientHelper.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=" + std::to_string(onTimeMean) + "]"));
    clientHelper.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=" + std::to_string(offTimeMean) + "]"));

    ApplicationContainer clientApps;
    Ptr<Node> clientNode = nodes.Get(0);
    clientApps.Add(clientHelper.Install(clientNode));

    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));

    ApplicationContainer serverApps;
    Ptr<Node> destinationNode = nodes.Get(6);
    serverApps.Add(sinkHelper.Install(destinationNode)); // Only destination receives

    clientApps.Start(Seconds(1.0));
    const double CLIENT_STOP_TIME = simulationTime - 2.0;
    clientApps.Stop(Seconds(CLIENT_STOP_TIME));
    serverApps.Start(Seconds(0.0));
    serverApps.Stop(Seconds(simulationTime));

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

    NS_LOG_INFO("================ NODE DATA ================");
    // Set node colors and descriptions
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        auto& role = nodeRoles[i];
        anim.UpdateNodeColor(nodes.Get(i), role.second[0], role.second[1], role.second[2]);
        anim.UpdateNodeDescription(nodes.Get(i), role.first);
        TORMonitor::PrintNodeStats(nodes.Get(i), role.first);
        NS_LOG_INFO(""); // Add a new line between nodes
    }

    // Print node positions
    NS_LOG_INFO("================ NODE POSITIONS ================");
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        Ptr<MobilityModel> mobilityModel = nodes.Get(i)->GetObject<MobilityModel>();
        Vector position = mobilityModel->GetPosition();
        NS_LOG_INFO("Node " << i << " Position: (" << position.x << ", " << position.y << ", " << position.z << ")");
    }
    NS_LOG_INFO("");

    // Initialize encryption keys
    TOREncryption::InitializeKeys(6);

    // Create a circuit
    std::vector<uint32_t> circuitPath = {0, 1, 2, 3, 4, 5, 6};
    TORCircuit circuit = CreateCircuit(123, circuitPath, 6);
    circuits.emplace(circuit.circuitId, circuit);
    NS_LOG_INFO("");

    // Simulate packet transmission and encryption
    Simulator::Schedule(Seconds(2.0), [&](){
        // Create a TOR packet
        TORPacket packet;
        packet.sequenceNumber = 1;
        packet.originalData = initialData;
        packet.data = initialData;
        packet.timestamp = Simulator::Now().GetSeconds();
        packet.hopCount = 0;
        packet.sourceNode = "Client";
        packet.destinationNode = "Destination";
        packet.circuitId = circuit.circuitId;
        packet.isControl = false;
        packet.protocol = 6; // TCP
        packet.numLayers = circuit.keys.size();
        packet.currentLayer = 0;

        NS_LOG_INFO("================ ENCRYPTION DATA ==================");
        NS_LOG_INFO("Original Packet Data: " << packet.data);

        // Calculate checksum and encrypt at client
        packet.CalculateChecksum();
        NS_LOG_INFO("");
	//NS_LOG_INFO("==ENCRYPTION DATA==");
        NS_LOG_INFO("  Keys: ");
        for (const std::string& key : circuit.keys) {
            std::stringstream key_ss;
            for (char c : key) {
                key_ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
            }
            NS_LOG_INFO("    Key (hex): " << key_ss.str());
        }
	NS_LOG_INFO("");
        packet.EncryptPacket(circuit.keys[0]);
        NS_LOG_INFO("Packet Data after Client Encryption: " << packet.data);

        // Simulate packet forwarding through the TOR network
        Ptr<Node> clientNode = NodeList::GetNode(0);
        Ptr<Node> entryNode = NodeList::GetNode(1);
        SendPacket(clientNode, entryNode, packet, packet.protocol);
        //NS_LOG_INFO("==ENCRYPTION DATA==");
	NS_LOG_INFO("");
        ProcessHop(packet, 0, circuit.keys, 1);
        //NS_LOG_INFO("==ENCRYPTION DATA==");
	NS_LOG_INFO("");
        ProcessHop(packet, 1, circuit.keys, 2);
        //NS_LOG_INFO("==ENCRYPTION DATA==");
	NS_LOG_INFO("");
        ProcessHop(packet, 2, circuit.keys, 3);
        //NS_LOG_INFO("==ENCRYPTION DATA==");
	NS_LOG_INFO("");
        ProcessHop(packet, 3, circuit.keys, 4);
        //NS_LOG_INFO("==ENCRYPTION DATA==");
	NS_LOG_INFO("");
        ProcessHop(packet, 4, circuit.keys, 5);

        // Exit Node Policy Check
        if (ExitNodePolicy(packet, 6)) {
            // Decrypt at Destination
            //NS_LOG_INFO("==ENCRYPTION DATA==");
            //NS_LOG_INFO=("");
	    packet.DecryptPacket(circuit.keys[5]);
            NS_LOG_INFO("Packet Data after Destination Decryption: " << packet.data);
            packet.hopCount++;
            packet.route.push_back(6);
            NS_LOG_INFO("");
            PrintPacketHeader(packet);
            NS_LOG_INFO("");
        } else {
            NS_LOG_INFO("Packet dropped at exit node due to policy.");
        }
 });

    Simulator::Schedule(Seconds(simulationTime), &Simulator::Stop);

    Simulator::Run();

    // Print detailed statistics
    flowMonitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();

    NS_LOG_INFO("================ TOR NETWORK STATISTICS ================");
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
        NS_LOG_INFO("  Delay: " << (stat.second.rxPackets > 0 ? stat.second.delaySum.GetSeconds() / stat.second.rxPackets : 0) << " seconds");
        NS_LOG_INFO("  Lost Packets: " << stat.second.lostPackets);
        NS_LOG_INFO("  Packet Loss Rate: " << (stat.second.txPackets > 0 ? (double)stat.second.lostPackets / stat.second.txPackets * 100 : 0) << "%");
        NS_LOG_INFO("  Throughput: " << (stat.second.rxBytes * 8) / (stat.second.timeLastRxPacket.GetSeconds() - stat.second.timeFirstTxPacket.GetSeconds()) / 1000000 << " Mbps");
        NS_LOG_INFO("  End-to-End Delay: " << (stat.second.rxPackets > 0 ? stat.second.delaySum.GetSeconds() / stat.second.rxPackets : 0) << " seconds");
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
NS_LOG_INFO("Average Delay: " << (totalRxPackets > 0 ? totalDelay/totalRxPackets : 0) << " seconds");
NS_LOG_INFO("Packet Delivery Ratio: " << (totalTxPackets > 0 ? (double)totalRxPackets/totalTxPackets * 100 : 0) << "%");
    NS_LOG_INFO("Simulation Time: " << simulationTime << " seconds");

    if (simulationTime < 3.0) {
        NS_LOG_INFO("");
        NS_LOG_INFO("Warning: The simulation time is less than 3 seconds. The network may not have had enough time to initialize properly.");
    }

    Simulator::Destroy();
    return 0;
}
