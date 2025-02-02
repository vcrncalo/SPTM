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
#include <vector>
#include <memory>
#include <map>

using namespace ns3;

#include "TOR_packet.h"
#include "TOREncryption.h"

NS_LOG_COMPONENT_DEFINE("TORNetworkExample");

uint32_t totalRxTorPackets = 0; // Track total received TOR packets

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

std::map<uint32_t, TORCircuit> circuits;

bool SendPacket(Ptr<Node> fromNode, Ptr<Node> toNode, TORPacket packet, uint16_t protocol) {
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
    if (socket->Send(p) == -1) {
        return false;
    }
    if (!packet.VerifyChecksum()) {
        throw std::runtime_error("Packet checksum verification failed");
    }
    return true;
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
    NS_LOG_INFO("  Packet Size: " << packet.packetSize << " bytes");
    NS_LOG_INFO("  Packet Type: " << (packet.packetType == DATA_PACKET ? "DATA" : (packet.packetType == CONTROL_PACKET ? "CONTROL" : "UNKNOWN")));
    NS_LOG_INFO("  Route: ");
     for (uint32_t nodeId : packet.route) {
        NS_LOG_INFO("    Node ID: " << nodeId);
    }
    NS_LOG_INFO("  Protocol: " << packet.protocol);
}

bool TORPacket::EncryptPacket(uint32_t layer) {
    std::stringstream data_ss_before, data_ss_after;
    for (char c : data) {
        data_ss_before << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
    }
    NS_LOG_INFO("=========================================");
    NS_LOG_INFO("");
    NS_LOG_INFO("Packet Data before Encryption at Layer " << layer << " (hex): " << data_ss_before.str());
    NS_LOG_INFO("");
    NS_LOG_INFO("=========================================");
    try {
        data = TOREncryption::EncryptLayer(data, layer);
    } catch (const std::exception& e) {
        NS_LOG_ERROR("Encryption failed at layer " << layer << ": " << e.what());
        return false;
    }
    return true;
    for (char c : data) {
        data_ss_after << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
    }
    NS_LOG_INFO("=========================================");
    NS_LOG_INFO("");
    NS_LOG_INFO("Packet Data after Encryption at Layer " << layer << " (hex): " << data_ss_after.str());
    NS_LOG_INFO("");
    NS_LOG_INFO("=========================================");
}

bool TORPacket::DecryptPacket(uint32_t layer) {
    std::stringstream data_ss_before, data_ss_after;
    for (char c : data) {
        data_ss_before << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
    }
    NS_LOG_INFO("=========================================");
    NS_LOG_INFO("");
    NS_LOG_INFO("Packet Data before Decryption at Layer " << layer << " (hex): " << data_ss_before.str());
    NS_LOG_INFO("");
    NS_LOG_INFO("=========================================");
    try {
        data = TOREncryption::DecryptLayer(data, layer);
    } catch (const std::exception& e) {
        NS_LOG_ERROR("Decryption failed at layer " << layer << ": " << e.what());
        return false;
    }
    return true;
    for (char c : data) {
        data_ss_after << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
    }
    NS_LOG_INFO("=========================================");
    NS_LOG_INFO("");
    NS_LOG_INFO("Packet Data after Decryption at Layer " << currentLayer << " (hex): " << data_ss_after.str());
    NS_LOG_INFO("");
    NS_LOG_INFO("=========================================");
}

void ForwardPacket(Ptr<Node> fromNode, Ptr<Node> toNode, TORPacket packet, uint32_t nextNodeId) {
    if (!SendPacket(fromNode, toNode, packet, packet.protocol)) {
        NS_LOG_ERROR("Failed to send packet from node " << fromNode->GetId() << " to node " << nextNodeId);
        return;
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
    if (1 != EVP_DigestUpdate(mdctx, reinterpret_cast<const unsigned char*>(&packetSize), sizeof(packetSize))) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::CalculateChecksum: EVP_DigestUpdate failed for packetSize");
    }
    if (1 != EVP_DigestUpdate(mdctx, reinterpret_cast<const unsigned char*>(&packetType), sizeof(packetType))) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::CalculateChecksum: EVP_DigestUpdate failed for packetType");
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
    if (1 != EVP_DigestUpdate(mdctx, reinterpret_cast<const unsigned char*>(&packetSize), sizeof(packetSize))) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::VerifyChecksum: EVP_DigestUpdate failed for packetSize");
    }
    if (1 != EVP_DigestUpdate(mdctx, reinterpret_cast<const unsigned char*>(&packetType), sizeof(packetType))) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("TORPacket::VerifyChecksum: EVP_DigestUpdate failed for packetType");
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
    NS_LOG_INFO("ProcessHop: Node ID = " << nodeId << ", Destination = " << packet.destinationNode << ", Layer = " << layer);
    if (layer >= keys.size()) {
        NS_LOG_ERROR("Invalid layer: " << layer);
        return;
    }
    packet.route.push_back(nodeId);
    if (!packet.DecryptPacket(static_cast<uint32_t>(layer))) {
        NS_LOG_ERROR("Failed to decrypt packet at layer " << layer);
        return;
    }
    NS_LOG_INFO("=========================================");
    NS_LOG_INFO("");
    NS_LOG_INFO("Packet Data after Decryption at Layer " << layer << ": " << packet.data);

    packet.hopCount++;
    bool isFinalDestination = (packet.destinationNode == "Destination" && nodeId == 6);
    if (isFinalDestination && !ExitNodePolicy(packet, nodeId)) {
        NS_LOG_ERROR("Exit node policy violation at node " << nodeId);
        return;
    }

    if (static_cast<size_t>(layer + 1) < keys.size()) {
        if (!packet.EncryptPacket(static_cast<uint32_t>(layer + 1))) {
            NS_LOG_ERROR("Failed to encrypt packet at layer " << layer + 1);
            return;
        }
    }

    // Forward the packet to the next node in the path
    if (!isFinalDestination) {
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
            ForwardPacket(fromNode, toNode, packet, nextNodeId);
            // Schedule the next hop
            EventId event = Simulator::Schedule(Seconds(0.001), &ProcessHop, packet, layer + 1, keys, nextNodeId);
            if (event == EventId()) {
                NS_LOG_ERROR("Failed to schedule next hop for packet at layer " << layer + 1);
                return;
            }
        } else {
            NS_LOG_INFO("Packet reached end of circuit path.");
            NS_LOG_INFO("");
            PrintPacketHeader(packet);
            NS_LOG_INFO("");

            // Check if the packet has reached the destination node
            if (packet.destinationNode == "Destination" && nodeId == 6) {
                if (packet.sourceNode != "Destination") {
                    NS_LOG_INFO("Packet reached destination, initiating return trip.");
                    // Reverse the route
                    std::reverse(packet.route.begin(), packet.route.end());
                    packet.currentLayer = packet.numLayers - 1;
                    packet.destinationNode = "Client";
                    packet.sourceNode = "Destination";
                    // Start the return trip
                    Ptr<Node> fromNode = NodeList::GetNode(nodeId);
                    Ptr<Node> toNode = NodeList::GetNode(5); // Send back to exit node
                    ForwardPacket(fromNode, toNode, packet, 5);
                    Simulator::Schedule(Seconds(0.002), &ProcessHop, packet, packet.currentLayer, keys, nodeId);
                }
            } else if (packet.destinationNode == "Destination" && nodeId != 6) {
                // Forward the packet to the destination node
                Ptr<Node> fromNode = NodeList::GetNode(nodeId);
                Ptr<Node> toNode = NodeList::GetNode(6); // Destination node ID is 6
                ForwardPacket(fromNode, toNode, packet, 6);
                totalRxTorPackets++;
            }
        }
    } else {
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
            ForwardPacket(fromNode, toNode, packet, nextNodeId);
            // Schedule the next hop
            Simulator::Schedule(Seconds(0.001), &ProcessHop, packet, layer + 1, keys, nextNodeId);
        } else {
            NS_LOG_INFO("Packet reached end of circuit path.");
            NS_LOG_INFO("");
            PrintPacketHeader(packet);
            NS_LOG_INFO("");
            // Start the return trip
            Ptr<Node> fromNode = NodeList::GetNode(nodeId);
            Ptr<Node> toNode = NodeList::GetNode(5); // Send back to exit node
            ForwardPacket(fromNode, toNode, packet, 5);
            Simulator::Schedule(Seconds(0.001), &ProcessHop, packet, packet.currentLayer, keys, nodeId);
        }
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
    std::string queueSize = "2000p";
    uint16_t port = 9001;
    uint32_t numPackets = 1; // Default number of packets
    uint32_t totalTxTorPackets = 0; // Track total transmitted TOR packets

    cmd.AddValue("initialData", "Initial data for the packet", initialData);
    cmd.AddValue("simulationTime", "Simulation time in seconds", simulationTime);
    cmd.AddValue("dataRate", "Data rate for the client application", dataRate);
    cmd.AddValue("queueSize", "Queue size for the point-to-point links", queueSize);
    cmd.AddValue("port", "Port number for the client and server applications", port);
    cmd.AddValue("numPackets", "Number of TOR packets to send", numPackets);
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

    // Create all packets
    std::vector<TORPacket> packets;
    for (uint32_t i = 0; i < numPackets; ++i) {
        TORPacket packet;
        packet.sequenceNumber = i + 1;
        packet.originalData = initialData;
        packet.data = initialData;
        packet.timestamp = Simulator::Now().GetSeconds();
        packet.hopCount = 0;
        packet.sourceNode = "Client";
        packet.destinationNode = "Destination";
        packet.circuitId = circuit.circuitId;
        packet.isControl = false;
        packet.protocol = 6; // TCP
        packet.packetType = DATA_PACKET;
        packet.numLayers = circuit.keys.size();
        packet.currentLayer = 0;
        NS_LOG_INFO("================ ENCRYPTION DATA ==================");
        NS_LOG_INFO("Original Packet Data: " << packet.data);
        packet.packetSize = packet.data.size();

        // Calculate checksum and encrypt at client
        packet.CalculateChecksum();
        NS_LOG_INFO("");
        NS_LOG_INFO("  Keys: ");
        for (const std::string& key : circuit.keys) {
            std::stringstream key_ss;
            for (char c : key) {
                key_ss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << (int)(unsigned char)c;
            }
            NS_LOG_INFO("    Key (hex): " << key_ss.str());
        }
        NS_LOG_INFO("");
        packet.EncryptPacket(static_cast<uint32_t>(0));
        NS_LOG_INFO("Packet Data after Client Encryption: " << packet.data);
        packets.push_back(packet);
        totalTxTorPackets++;
    }

    // Schedule the sending of all packets at once
    Simulator::Schedule(Seconds(2.0), [&, packets](){
        for (const auto& packet : packets) {
            // Simulate packet forwarding through the TOR network
            Ptr<Node> clientNode = NodeList::GetNode(0);
            Ptr<Node> entryNode = NodeList::GetNode(1);
            // Schedule the first hop from the client node
            Simulator::Schedule(Seconds(0.001), &ProcessHop, packet, 0, circuit.keys, 0);
        }
    });

    Simulator::Schedule(Seconds(simulationTime), &Simulator::Stop);

    Simulator::Run();

    // Print detailed statistics
    flowMonitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();
    std::vector<double> packetDelays; // Store packet delays for quantile diagram

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
        if (stat.second.rxPackets > 0) {
            packetDelays.push_back(stat.second.delaySum.GetSeconds() / stat.second.rxPackets);
        }
        NS_LOG_INFO("");
    }

    // Function to generate quantile diagram data for packet delays
    auto generateQuantileDiagramData = [&](const std::vector<double>& delays) {
        if (delays.empty()) {
            NS_LOG_INFO("No packet delays to analyze.");
            return;
        }

        std::vector<double> sortedDelays = delays;
        std::sort(sortedDelays.begin(), sortedDelays.end());

        // Create a file to store the quantile data
        std::ofstream quantileFile("quantile_data.dat");
        if (!quantileFile.is_open()) {
            NS_LOG_ERROR("Failed to open quantile_data.dat for writing.");
            return;
        }

        std::vector<double> quantiles = {0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1.0};
        for (double q : quantiles) {
            size_t index = static_cast<size_t>(q * (sortedDelays.size() - 1));
            quantileFile << q << "\t" << sortedDelays[index] << "\n";
        }

        quantileFile.close();
        NS_LOG_INFO("Quantile data written to quantile_data.dat.");
    };

    // Call the function to generate the quantile diagram data
    generateQuantileDiagramData(packetDelays);

    // Calculate and print overall network statistics
    uint64_t totalTxBytes = 0, totalRxBytes = 0;
    uint32_t totalTxPackets = 0, totalRxPackets = 0, totalLostPackets = 0;
    double totalDelay = 0;

    for (auto& stat : stats) {
        totalTxBytes += stat.second.txBytes;
        totalRxBytes += stat.second.rxBytes;
        totalTxPackets += stat.second.txPackets;
        totalRxPackets += stat.second.rxPackets;
        totalLostPackets += stat.second.lostPackets;
        totalDelay += stat.second.delaySum.GetSeconds();
    }
    
    totalLostPackets += (totalTxTorPackets > totalRxTorPackets) ? (totalTxTorPackets - totalRxTorPackets) : 0;

    NS_LOG_INFO("Overall Network Statistics:");
    NS_LOG_INFO("Total Transmitted Packets: " << totalTxPackets); // Total packets transmitted by all source nodes
    NS_LOG_INFO("Total Received Packets: " << totalRxPackets);   // Total packets received by all destination nodes
    NS_LOG_INFO("Total Lost Packets: " << totalLostPackets);
    NS_LOG_INFO("Average Delay: " << (totalRxPackets > 0 ? totalDelay / totalRxPackets : 0) << " seconds");
    NS_LOG_INFO("Packet Delivery Ratio: " << (totalTxPackets > 0 ? (double)totalRxPackets / totalTxPackets * 100 : 0) << "%");
    NS_LOG_INFO("Total Transmitted TOR Packets: " << totalTxTorPackets);
    NS_LOG_INFO("Total Received TOR Packets: " << totalRxTorPackets);
    NS_LOG_INFO("Max Simulation Time: " << simulationTime << " seconds");

    if (simulationTime < 3.0) {
        NS_LOG_INFO("");
        NS_LOG_INFO("Warning: The simulation time is less than 3 seconds. The network may not have had enough time to initialize properly.");
    }

    Simulator::Destroy();
    return 0;
}
