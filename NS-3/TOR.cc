// Including necessary libraries.
/**
 * @file
 * @brief This code will allow transfer of packets, udp-echo-client.cc located in src/applications/model allows sending of packets with string passed as data, while udp-echo-server.cc in the same directory allows the packets to be received.
 * */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/mobility-module.h"
#include <iostream>
#include <string>
#include <vector>
#include <fstream> // This is needed for creating the output file.

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SimpleTOR");

struct PacketTrace {
    double sendTime;
    std::string path;
};

std::map<uint32_t, PacketTrace> packetTracker;
/**
 * @brief Here, we are declaring node names for all nodes in the network topology.
 * */
std::vector<std::string> nodeNames = {"Client", "Entry", "Relay1", "Relay2", "Relay3", "Exit", "Destination"};

/**
 * @brief This is the variable which gets assigned a value of the time when the first packet was transmitted
 * */
static Time g_firstPacketTime = Seconds(0.0);
/**
 * @brief This is the variable which gets assigned a value of the time when the last packet was transmitted.
 * */
static Time g_lastPacketTime = Seconds(0.0);
/**
 * @brief This is a boolean value for the first packet which can be true or false.
 * */
static bool g_firstPacket = true;

static std::map<uint32_t, double> PacketStartTimes;
/**
 * @brief This is a variable, type double, which means it stores decimal values, and it stores the value of the total delay of the network.
 * */
static double totalDelay = 0.0;
/**
 * @btief This is a variable, type int, and it stores packet count.
 * */
static int packetCount = 0; 
/**
 * @brief This is an unsigned variable type, which means that it cannot have negative values, and the range for the numbers it can have is from 0 to 2^32. This variable stores the amount of sent bytes.
 * */
uint32_t m_bytes_sent = 0;
/**
 * @brief This variable stores the amount of received bytes.
 * */
uint32_t m_bytes_received = 0;
/**
 * @brief This variable stores the amount of sent packets.
 * */
uint32_t m_packets_sent = 0;
/**
 * @brief This variable stores the amount of received packets.
 * */
uint32_t m_packets_received = 0;

//Create help variable m_time
double m_time = 0;

//Create c++ map for measuring delay time
std::map<uint32_t, double> m_delayTable;

/**
 * @brief This is a function which handles the sending of packets.
 *
 * @param p This is the packet that is being sent.
 * */
static void SentPacket(Ptr<const Packet> p) {
/**
* @brief The number of sent bytes gets increased, it adds the size of the packet that is being sent to the current amount of sent bytes.
* */ 
    m_bytes_sent += p->GetSize();
/**
* @brief The variable which tracks the number of sent packets increases. 
* */ 
    m_packets_sent++;
/*! This if statement checks if the first packet is being sent, and if it is, the variable which is declared for storing the time of the first sent packets actually gets that value assigned to itself. */ 
    if (g_firstPacket) {
    	g_firstPacketTime = Simulator::Now();
    	g_firstPacket = false;
    }
    
    g_lastPacketTime = Simulator::Now();
    
/**
 * @brief The start time of each sent packet gets extracted. This applies to every packet and the Uid of that packet gets extracted so that the message which prints at what time the specific packet got sent.
 * */
    PacketStartTimes[p->GetUid()] = Simulator::Now().GetSeconds(); 
/**
 * @brief This message prints when a certain packet got sent.
 * */
    std::cout << "\nPacket " << p->GetUid()+1 << " sent at time " <<    Simulator::Now().GetSeconds() << "s" << std::endl;
   
}

/**
 * @brief This is a function which handles the process of receiving packets.
 * */
static void ReceivedPacket(Ptr<const Packet> p) {
/**
 * @brief This will allow an output file to be created, also, data can be appended to this file because of std::ios::app which is included. If we omit that, we would keep creating the file without appending data to it, which wouldn't be a solution because we need to track the data for every packet so that we can eventually use gnuplot to plot the captured data, not just the final data for the final packet which was sent.
 * */
    std::ofstream output_file("output.txt", std::ios::app); // This will create and open the file and append data to it.
    
    m_bytes_received += p->GetSize();
    m_packets_received++;

    /*
    //HELP LINES USED FOR TESTING
    std::cout << "\n ..................ReceivedPacket....." << p->GetUid() << "..." <<  p->GetSize() << ".......  \n";
    p->Print(std::cout);
    std::cout << "\n ............................................  \n";
    */

/**
 * @brief This variable stores the time when the packet was received. 
 * */
        double endTime = Simulator::Now().GetSeconds();
/**
 * @brief This variable stores the time when the packet was sent. 
 * */
        double startTime = PacketStartTimes[p->GetUid()];
/**
 * @brief This variable stores the packet delay which is calculated by subtracting start time from the end time. 
 * */
        double packetDelay = endTime - startTime;
    
        //Ptr<Packet> packetCopy = p->Copy();
    	  //DecryptPacket (packetCopy);
        
        totalDelay += packetDelay;
        packetCount++;
/**
 * @brief This represents the time when the packet was received.
 * */   
        double duration = Simulator::Now().GetSeconds();
/**
 * @brief This variable stores the throughput value, which is calculated by multiplying received bytes by 8 and dividing that by the duration. The value for the throughput is displayed in bits per second.
 * */
        double throughputBps = (m_bytes_received * 8.0) / duration;
        //double averageDelay = totalDelay/packetCount;
/**
 * @brief Output file gets created with contents of:
 * 
 * - Duration;
 * - Sent packets;
 * - Received packets;
 * - Throughput in bits per second;
 * - Packet delay.
 * */
        output_file << duration << " " << m_packets_sent << " " << m_packets_received << " " << throughputBps << " " << packetDelay << std::endl; // This will create an output file with: duration, sent packets, received packets, throughput and the packet delay with spaces between them.
/**
 * @brief This allows the output file to be closed after writing.
 * */
        output_file.close(); // This closes the output file after writing.
        
/**
 * @brief This message prints the time when the packet was received.
 * */
        std::cout << "\nPacket " << p->GetUid()+1 << " received at time " << endTime << "s with delay of: "<< packetDelay << " s " << std::endl;
    
}

/**
 * @brief This function allows the tor network statistic to be printed out, which prints all relevant data about the network simulation.
 * */
void Ratio(){

    std::cout << "\n=== TOR network statistics ===\n" << std::endl;
    std::cout << "Transmission summary:" << std::endl;
    std::cout << "------------------------------------" << std::endl;
    std::cout << "Total bytes sent:\t  " << m_bytes_sent << std::endl;
    std::cout << "Total bytes received:\t  " << m_bytes_received << std::endl;
    std::cout << "Total packets sent:\t  " << m_packets_sent << std::endl;
    std::cout << "Total packets received:\t  " << m_packets_received << std::endl;
    std::cout << "Delivery ratio (bytes):\t  " << (float)m_bytes_received/(float)m_bytes_sent * 100 << "%" << std::endl;
    std::cout << "Delivery ratio (packets): " << (float)m_packets_received/(float)m_packets_sent * 100 << "%" << std::endl;
              
    double duration = Simulator::Now().GetSeconds();
    double throughputBps = (m_bytes_received * 8.0) / duration;
    if (duration > 0){
    	
    	std::cout << "Troughput (bps):\t  " << throughputBps << " bps " << std::endl;
    	std::cout << "Troughput (kbps):\t  " << throughputBps/1000.0 << " kbps " << std::endl;
    }   
              
    if (packetCount > 0) {
       
       std::cout << "Average end-to-end delay: " << totalDelay/packetCount << "s" << std::endl; 
    
    }          
    std::cout << "------------------------------------" << std::endl;


  std::cout << "Created output file: output.txt" << std::endl;
  std::cout << "------------------------------------" << std::endl;

}

/**
 * @brief This is the main function which gets called once the simulation starts.
 * */
int main(int argc, char *argv[]){
/** 
 * @brief If output.txt exists in the directory where the simulation is started, it will be replaced with output.txt with no content.
    std::ofstream output_file("output.txt"); // Replace output_txt if it was created before.
*/
    // LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);

Config::SetDefault ("ns3::Ipv4GlobalRouting::RespondToInterfaceEvents",BooleanValue(true));
/**
 * @brief Simulation time is assigned to this variable.
 * */

    double simulationTime = 20; // 20 seconds.
/**
 * @brief This variable stores the maximum amount of packets.
 * */
    double maxPackets = 10; // 10 packets.
 
    Packet::EnablePrinting();
    PacketMetadata::Enable();  
 
/**
 * @brief This allows the user to specify parameters which could be changed while running the simulation, such as: ./ns3 run scratch/TOR.cc -- -maxPackets=5 -simulationTime=30
 * */
    CommandLine cmd;
    cmd.AddValue ("simulationTime", "simulationTime", simulationTime);
    cmd.AddValue ("maxPackets", "maxPackets", maxPackets);
    cmd.Parse (argc, argv);
  
    Time::SetResolution (Time::NS);
    //LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_ALL);
    //LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_ALL);
    LogComponentEnable ("SimpleTOR", LOG_LEVEL_ALL);

/**
 * @brief Node container is specified.
 * */
    NodeContainer nodes;
/**
 * @brief 7 nodes are being created.
 * */
    nodes.Create(7);
    
    //Point to Point links
    PointToPointHelper pointToPoint;
/**
 * @brief Data rate parameter is being assigned to the point-to-point link.
 * */
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
/**
 * @brief Delay parameter is being assigned to the point-to-point link.
 * */
    pointToPoint.SetChannelAttribute("Delay", StringValue("25ms")); 

/**
 * @brief This holds a collection of network devices, such as wifi or ethernet devices.
 * */    
    NetDeviceContainer devices[6];
/**
 * @brief This holds IPv4 addresses of network devices.
 * */
    Ipv4InterfaceContainer interfaces[6];
    
/**
 * @brief This installs a network stack on nodes.
 * */
    InternetStackHelper stack;
    stack.Install(nodes);
    
/**
 * @brief This assigns IPv4 addresses to network devices.
 * */
    Ipv4AddressHelper address;
    
/**
 * @brief This creates a P2P link between nodes 0 and 1.
 * */
    address.SetBase("10.1.1.0", "255.255.255.0");
    interfaces[0] = address.Assign(pointToPoint.Install(nodes.Get(0), nodes.Get(1)));
    
    address.SetBase("10.1.2.0", "255.255.255.0");
    interfaces[1] = address.Assign(pointToPoint.Install(nodes.Get(1), nodes.Get(2)));
    
    address.SetBase("10.1.3.0", "255.255.255.0");
    interfaces[2] = address.Assign(pointToPoint.Install(nodes.Get(2), nodes.Get(3)));
    
    address.SetBase("10.1.4.0", "255.255.255.0");
    interfaces[3] = address.Assign(pointToPoint.Install(nodes.Get(3), nodes.Get(4)));
    
    address.SetBase("10.1.5.0", "255.255.255.0");
    interfaces[4] = address.Assign(pointToPoint.Install(nodes.Get(4), nodes.Get(5)));
    
    address.SetBase("10.1.6.0", "255.255.255.0");
    interfaces[5] = address.Assign(pointToPoint.Install(nodes.Get(5), nodes.Get(6)));
    
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    
    UdpEchoServerHelper echoServer(9);
    ApplicationContainer serverApp = echoServer.Install(nodes.Get(6));
    
/**
 * @brief This specifies the initialisation time of the server. 
 * */
    serverApp.Start(Seconds(1.0));
/**
 * @brief This specifies the time when the server stops responding. 
 * */
    serverApp.Stop(Seconds(simulationTime));
    
    UdpEchoClientHelper echoClient(interfaces[5].GetAddress(1), 9);
    echoClient.SetAttribute("MaxPackets", UintegerValue(maxPackets));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(0.1)));
    
    ApplicationContainer clientApp = echoClient.Install(nodes.Get(0));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(simulationTime));
    
    // Connect trace sources for packet tracking
    Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::UdpEchoClient/Tx", MakeCallback(&SentPacket));
    Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::UdpEchoServer/Rx", MakeCallback(&ReceivedPacket));
       
    // Mobility Setup
    MobilityHelper mobility;
/**
 * @brief This creates and allocates a mobility model and installs it for the nodes.
 * */
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                              "MinX", DoubleValue(50.0), 
                              "MinY", DoubleValue(80.0),  
                              "DeltaX", DoubleValue(60.0), 
                              "DeltaY", DoubleValue(70.0),
                              "GridWidth", UintegerValue(4),
                              "LayoutType", StringValue("RowFirst"));

    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // NetAnim
/**
 * @brief This will create an xml file which can later be viewed in NetAnim which provides network visualisation.
 * */
    AnimationInterface anim("TOR.xml");
/**
 * @brief This sets the maximum amounts of packets per trace file.
 * */
    anim.SetMaxPktsPerTraceFile(5000);
 /**
 * @brief This specifies node descriptions.
 *
 * Apart from this, we choose node colors.
 *
 * */
    anim.UpdateNodeDescription(0, "Client");
    anim.UpdateNodeDescription(1, "Entry Guard");
    anim.UpdateNodeDescription(2, "Relay 1");
    anim.UpdateNodeDescription(3, "Relay 2");
    anim.UpdateNodeDescription(4, "Relay 3");
    anim.UpdateNodeDescription(5, "Exit");
    anim.UpdateNodeDescription(6, "Destination");
    
    anim.UpdateNodeColor(0, 255, 0, 0); // Red for Client
    anim.UpdateNodeColor(1, 0, 255, 0); // Green for Entry Guard
    anim.UpdateNodeColor(2, 0, 0, 255); // Blue for Relay 1
    anim.UpdateNodeColor(3, 255, 255, 0); // Yellow for Relay 2
    anim.UpdateNodeColor(4, 255, 0, 255); // Purple for Relay 3
    anim.UpdateNodeColor(5, 0, 255, 255); // Cyan for Exit
    anim.UpdateNodeColor(6, 128, 128, 128); // Gray for Destination
    ;
    
/**
 * @brief Network tracing is enabled here.
 * */
    pointToPoint.EnablePcapAll("tor_packet_trace");
    
    Simulator::Schedule(Seconds(simulationTime), &Ratio);

/**
 * @brief This allows the simulation to start.
 * */
    Simulator::Run();
/**
 * @brief This frees up resources which were allocated to the simulation while it was running.
 * */
    Simulator::Destroy();
    
/**
 * @brief If 0 is returned, that means that code execution was successfull.
 * */
    return 0;
}

