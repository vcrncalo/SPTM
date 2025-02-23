// Including necessary libraries.
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

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SimpleTOR");

struct PacketTrace {
    double sendTime;
    std::string path;
};

std::map<uint32_t, PacketTrace> packetTracker;
std::vector<std::string> nodeNames = {"Client", "Entry", "Relay1", "Relay2", "Relay3", "Exit", "Destination"};

static Time g_firstPacketTime = Seconds(0.0);
static Time g_lastPacketTime = Seconds(0.0);
static bool g_firstPacket = true;

static std::map<uint32_t, double> PacketStartTimes;
static double totalDelay = 0.0;
static int packetCount = 0; 

//static const uint8_t KEY = 0x2A;

uint32_t m_bytes_sent = 0;
uint32_t m_bytes_received = 0;

uint32_t m_packets_sent = 0;
uint32_t m_packets_received = 0;

//Create help variable m_time
double m_time = 0;

//Create c++ map for measuring delay time
std::map<uint32_t, double> m_delayTable;

static void SentPacket(Ptr<const Packet> p) {
    m_bytes_sent += p->GetSize();
    m_packets_sent++;
	
    if (g_firstPacket) {
    	g_firstPacketTime = Simulator::Now();
    	g_firstPacket = false;
    }
    
    g_lastPacketTime = Simulator::Now();
    
    PacketStartTimes[p->GetUid()] = Simulator::Now().GetSeconds();
    
    std::cout << "\nPacket " << p->GetUid()+1 << " sent at time " <<    Simulator::Now().GetSeconds() << "s" << std::endl;
   
}

static void ReceivedPacket(Ptr<const Packet> p) {
    m_bytes_received += p->GetSize();
    m_packets_received++;

    /*
    //HELP LINES USED FOR TESTING
    std::cout << "\n ..................ReceivedPacket....." << p->GetUid() << "..." <<  p->GetSize() << ".......  \n";
    p->Print(std::cout);
    std::cout << "\n ............................................  \n";
    */

        double endTime = Simulator::Now().GetSeconds();
        double startTime = PacketStartTimes[p->GetUid()];
        double packetDelay = endTime - startTime;
        
        //Ptr<Packet> packetCopy = p->Copy();
    	//DecryptPacket (packetCopy);
        
        totalDelay += packetDelay;
        packetCount++;
        
        std::cout << "\nPacket " << p->GetUid()+1 << " received at time " << endTime << "s with delay of: "<< packetDelay << " s " << std::endl;
    
}

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
    if (duration > 0){
    	double troughputBps = (m_bytes_received * 8.0) / duration;
    	
    	std::cout << "Troughput (bps):\t  " << troughputBps << " bps " << std::endl;
    	std::cout << "Troughput (kbps):\t  " << troughputBps/1000.0 << " kbps " << std::endl;
    }   
              
    if (packetCount > 0) {
       
       std::cout << "Average end-to-end delay: " << totalDelay/packetCount << "s" << std::endl; 
    
    }          
    std::cout << "------------------------------------" << std::endl;
}

int main(int argc, char *argv[]){

// LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);

Config::SetDefault ("ns3::Ipv4GlobalRouting::RespondToInterfaceEvents",BooleanValue(true));

    double simulationTime = 20; // 20 seconds.
    double maxPackets = 10; // 10 packets.
 
    Packet::EnablePrinting();
    PacketMetadata::Enable ();  
 
    CommandLine cmd;
    cmd.AddValue ("simulationTime", "simulationTime", simulationTime);
    cmd.AddValue ("maxPackets", "maxPackets", maxPackets);
    cmd.Parse (argc, argv);
  
    Time::SetResolution (Time::NS);
    //LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_ALL);
    //LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_ALL);
    LogComponentEnable ("SimpleTOR", LOG_LEVEL_ALL);

    NodeContainer nodes;
    nodes.Create(7);
    
    //Point to Point links
    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    pointToPoint.SetChannelAttribute("Delay", StringValue("25ms")); 
    
    NetDeviceContainer devices[6];
    Ipv4InterfaceContainer interfaces[6];
    
    InternetStackHelper stack;
    stack.Install(nodes);
    
    Ipv4AddressHelper address;
    
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
    serverApp.Start(Seconds(1.0));
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
    AnimationInterface anim("TOR.xml");
    anim.SetMaxPktsPerTraceFile(5000);
    
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
    
    pointToPoint.EnablePcapAll("tor_packet_trace");
    
    Simulator::Schedule(Seconds(simulationTime), &Ratio);

    Simulator::Run();
    Simulator::Destroy();
    
    return 0;
}

