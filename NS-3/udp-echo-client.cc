/*
 * Copyright 2007 University of Washington
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
/** 
 * @file
 * @brief This file allows the sending of packets in TOR.cc which is located in the scratch folder.
 * */

#include "udp-echo-client.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/log.h"
#include "ns3/nstime.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/socket.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("UdpEchoClientApplication");

NS_OBJECT_ENSURE_REGISTERED(UdpEchoClient);

TypeId
UdpEchoClient::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::UdpEchoClient")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<UdpEchoClient>()
            .AddAttribute(
                "MaxPackets",
                "The maximum number of packets the application will send (zero means infinite)",
                UintegerValue(100),
                MakeUintegerAccessor(&UdpEchoClient::m_count),
                MakeUintegerChecker<uint32_t>())
            .AddAttribute("Interval",
                          "The time to wait between packets",
                          TimeValue(Seconds(1.0)),
                          MakeTimeAccessor(&UdpEchoClient::m_interval),
                          MakeTimeChecker())
            .AddAttribute("RemoteAddress",
                          "The destination Address of the outbound packets",
                          AddressValue(),
                          MakeAddressAccessor(&UdpEchoClient::m_peerAddress),
                          MakeAddressChecker())
            .AddAttribute("RemotePort",
                          "The destination port of the outbound packets",
                          UintegerValue(0),
                          MakeUintegerAccessor(&UdpEchoClient::m_peerPort),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("Tos",
                          "The Type of Service used to send IPv4 packets. "
                          "All 8 bits of the TOS byte are set (including ECN bits).",
                          UintegerValue(0),
                          MakeUintegerAccessor(&UdpEchoClient::m_tos),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute(
                "PacketSize",
                "Size of echo data in outbound packets",
                UintegerValue(100),
                MakeUintegerAccessor(&UdpEchoClient::SetDataSize, &UdpEchoClient::GetDataSize),
                MakeUintegerChecker<uint32_t>())
            .AddTraceSource("Tx",
                            "A new packet is created and is sent",
                            MakeTraceSourceAccessor(&UdpEchoClient::m_txTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource("Rx",
                            "A packet has been received",
                            MakeTraceSourceAccessor(&UdpEchoClient::m_rxTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource("TxWithAddresses",
                            "A new packet is created and is sent",
                            MakeTraceSourceAccessor(&UdpEchoClient::m_txTraceWithAddresses),
                            "ns3::Packet::TwoAddressTracedCallback")
            .AddTraceSource("RxWithAddresses",
                            "A packet has been received",
                            MakeTraceSourceAccessor(&UdpEchoClient::m_rxTraceWithAddresses),
                            "ns3::Packet::TwoAddressTracedCallback");
    return tid;
}

UdpEchoClient::UdpEchoClient()
{
    NS_LOG_FUNCTION(this);
    m_sent = 0;
    m_socket = nullptr;
    m_sendEvent = EventId();
    m_data = nullptr;
    m_dataSize = 0;
}

UdpEchoClient::~UdpEchoClient()
{
    NS_LOG_FUNCTION(this);
    m_socket = nullptr;

    delete[] m_data;
    m_data = nullptr;
    m_dataSize = 0;
}

void
UdpEchoClient::SetRemote(Address ip, uint16_t port)
{
    NS_LOG_FUNCTION(this << ip << port);
    m_peerAddress = ip;
    m_peerPort = port;
}

void
UdpEchoClient::SetRemote(Address addr)
{
    NS_LOG_FUNCTION(this << addr);
    m_peerAddress = addr;
}

void
UdpEchoClient::StartApplication()
{
    NS_LOG_FUNCTION(this);

    if (!m_socket)
    {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket(GetNode(), tid);
        NS_ABORT_MSG_IF(m_peerAddress.IsInvalid(), "'RemoteAddress' attribute not properly set");
        if (Ipv4Address::IsMatchingType(m_peerAddress))
        {
            if (m_socket->Bind() == -1)
            {
                NS_FATAL_ERROR("Failed to bind socket");
            }
            m_socket->SetIpTos(m_tos); // Affects only IPv4 sockets.
            m_socket->Connect(
                InetSocketAddress(Ipv4Address::ConvertFrom(m_peerAddress), m_peerPort));
        }
        else if (Ipv6Address::IsMatchingType(m_peerAddress))
        {
            if (m_socket->Bind6() == -1)
            {
                NS_FATAL_ERROR("Failed to bind socket");
            }
            m_socket->Connect(
                Inet6SocketAddress(Ipv6Address::ConvertFrom(m_peerAddress), m_peerPort));
        }
        else if (InetSocketAddress::IsMatchingType(m_peerAddress))
        {
            if (m_socket->Bind() == -1)
            {
                NS_FATAL_ERROR("Failed to bind socket");
            }
            m_socket->SetIpTos(m_tos); // Affects only IPv4 sockets.
            m_socket->Connect(m_peerAddress);
        }
        else if (Inet6SocketAddress::IsMatchingType(m_peerAddress))
        {
            if (m_socket->Bind6() == -1)
            {
                NS_FATAL_ERROR("Failed to bind socket");
            }
            m_socket->Connect(m_peerAddress);
        }
        else
        {
            NS_ASSERT_MSG(false, "Incompatible address type: " << m_peerAddress);
        }
    }

    m_socket->SetRecvCallback(MakeCallback(&UdpEchoClient::HandleRead, this));
    m_socket->SetAllowBroadcast(true);
    ScheduleTransmit(Seconds(0.));
}

void
UdpEchoClient::StopApplication()
{
    NS_LOG_FUNCTION(this);

    if (m_socket)
    {
        m_socket->Close();
        m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        m_socket = nullptr;
    }

    Simulator::Cancel(m_sendEvent);
}

void
UdpEchoClient::SetDataSize(uint32_t dataSize)
{
    NS_LOG_FUNCTION(this << dataSize);

    //
    // If the client is setting the echo packet data size this way, we infer
    // that she doesn't care about the contents of the packet at all, so
    // neither will we.
    //
    delete[] m_data;
    m_data = nullptr;
    m_dataSize = 0;
    m_size = dataSize;
}

uint32_t
UdpEchoClient::GetDataSize() const
{
    NS_LOG_FUNCTION(this);
    return m_size;
}

void
UdpEchoClient::SetFill(std::string fill)
{
    NS_LOG_FUNCTION(this << fill);

    uint32_t dataSize = fill.size() + 1;

    if (dataSize != m_dataSize)
    {
        delete[] m_data;
        m_data = new uint8_t[dataSize];
        m_dataSize = dataSize;
    }

    memcpy(m_data, fill.c_str(), dataSize);

    //
    // Overwrite packet size attribute.
    //
    m_size = dataSize;
}

void
UdpEchoClient::SetFill(uint8_t fill, uint32_t dataSize)
{
    NS_LOG_FUNCTION(this << fill << dataSize);
    if (dataSize != m_dataSize)
    {
        delete[] m_data;
        m_data = new uint8_t[dataSize];
        m_dataSize = dataSize;
    }

    memset(m_data, fill, dataSize);

    //
    // Overwrite packet size attribute.
    //
    m_size = dataSize;
}

void
UdpEchoClient::SetFill(uint8_t* fill, uint32_t fillSize, uint32_t dataSize)
{
    NS_LOG_FUNCTION(this << fill << fillSize << dataSize);
    if (dataSize != m_dataSize)
    {
        delete[] m_data;
        m_data = new uint8_t[dataSize];
        m_dataSize = dataSize;
    }

    if (fillSize >= dataSize)
    {
        memcpy(m_data, fill, dataSize);
        m_size = dataSize;
        return;
    }

    //
    // Do all but the final fill.
    //
    uint32_t filled = 0;
    while (filled + fillSize < dataSize)
    {
        memcpy(&m_data[filled], fill, fillSize);
        filled += fillSize;
    }

    //
    // Last fill may be partial
    //
    memcpy(&m_data[filled], fill, dataSize - filled);

    //
    // Overwrite packet size attribute.
    //
    m_size = dataSize;
}

void
UdpEchoClient::ScheduleTransmit(Time dt)
{
    NS_LOG_FUNCTION(this << dt);
    m_sendEvent = Simulator::Schedule(dt, &UdpEchoClient::Send, this);
}

/**
 * @brief This function handles sending of packets.
 * */
void
UdpEchoClient::Send()
{
    NS_LOG_FUNCTION(this);

    NS_ASSERT(m_sendEvent.IsExpired());

    Ptr<Packet> p;
    if (m_dataSize)
    {
        //
        // If m_dataSize is non-zero, we have a data buffer of the same size that we
        // are expected to copy and send.  This state of affairs is created if one of
        // the Fill functions is called.  In this case, m_size must have been set
        // to agree with m_dataSize
        //
        NS_ASSERT_MSG(m_dataSize == m_size,
                      "UdpEchoClient::Send(): m_size and m_dataSize inconsistent");
        NS_ASSERT_MSG(m_data, "UdpEchoClient::Send(): m_dataSize but no m_data");
        NS_LOG_INFO("HI");
        p = Create<Packet>(m_data, m_dataSize);
    }
    else
    {
        //
        // If m_dataSize is zero, the client has indicated that it doesn't care
        // about the data itself either by specifying the data size by setting
        // the corresponding attribute or by not calling a SetFill function.  In
        // this case, we don't worry about it either.  But we do allow m_size
        // to have a value different from the (zero) m_dataSize.
        
/**
 * @brief Creating a message that will be packet's data.
 * */
        std::string message = "Hello World!"; /**< This is a message that will be sent as packet's data. std::string is used to declare a variable with the string type, and we always put a semicolon at the end of the line of code. */
        uint32_t dataSize = message.size(); /**< This returns the size of the message. uint32_t can hold up to 2^32 values, and here we get the size of the message and assign it to the dataSize variable. */

/**
 * @brief Allocate a buffer to hold the message data.
 * */
        uint8_t* dataBuffer = new uint8_t[dataSize]; /** This line of code allocates a block of memory for an array of uint8_t elements. The size of the array is determined by the dataSize variable. uint8_t* is a pointer to the uint8_t variable and it stores the memory address of that variable. */
        memcpy(dataBuffer, message.c_str(), dataSize); /**< This copies dataSize number of bits from message.c_str to the dataBuffer. */ 
       
        uint8_t keys[] = {'A', 'B', 'C', 'F', 'E', 'D'}; /**< This declares keys which will be used in the encryption process. In the encryption process, the for loop iterates through this array from the first to the last element of the array, while in the decryption process it goes from the last to the first element of the array. */

        std::cout << "\n"; /**< This allows us to print a new line */
        std::cout << "-------------------------------" << std::endl;
        std::cout << "Packet data before encryption: ";
/**
 * @brief This for loops allows printing of packet data before encryption.
 * */
        for (uint32_t i = 0; i < dataSize; i++){
          std::cout << dataBuffer[i];
        }
       
        std::cout << "" << std::endl; 
        std::cout << "-------------------------------" << std::endl;
        std::cout << "" << std::endl;
        std::cout << "-------------------------------" << std::endl;
        
        // XOR encryption.
        int xor_counter = 0; /**< This counter is used in the for loop for encryption purposes. */
       
/**
 * @brief This loop essentially checks if the xor_counter is 6, and if it isn't, it breaks out of the loop. This is because the goal of this is to create 6 encryption layers with 6 different keys which have been specified in the keys array.
 * */ 
        while (true){ /**< We initiate a while loop */
          std::cout << "Packet data after encryption with layer " << xor_counter+1 << ": "; /**< Here, packet data after encryption on a certain layer gets printed. When the xor_counter is 0 for example, the XOR key that will be used for encryption is the 'A' character, and the layer which will be printed is 0 + 1 = 1. */
          for (uint32_t i = 0; i < dataSize; i++) { /**< This loop starts at 0 and stops when i ends up having the value of dataSize. We need this loop to iterate through the message which we are trying to encrypt. i is started with the uint32_t type, because if we assigned int as a type to it we would get a type mismatch error because of the dataSize type */
            dataBuffer[i] ^= keys[xor_counter];  /**< This is the dataBuffer which stores the message sent as packet data. We are iterating through that message in such a way that each character of that message ges encrypted with a specific XOR key chosen by the xor_counter which gets incremented by one with every iteration. */
            std::cout << dataBuffer[i]; /**< We are printing encrypted message data. Notice that we didn't use std::endl yet, because that would be printing those characters on a new line every single time, which is unwanted behaviour. */
          } 
          std::cout << "" << std::endl; /**< This is happening outside the for loop, this prints a new line. */
          xor_counter++; /**< The xor_counter is incremented so that we can move onto the next key of the array. */
          if (xor_counter == 6){ /**< When the xor_counter gets assigned a value of 6, the loop breaks because we would otherwise try to access values of the array which aren't there (there are 6 keys: 0-5). */
            break; /**< We break out of the loop in case the xor_counter gets assigned the value of 6. */
          }
        }
        
        std::cout << "-------------------------------" << std::endl;

/**
 * @brief Create the packet with the encrypted data.
 * */
        p = Create<Packet>(dataBuffer, dataSize); /**< Finally, the packet with encrypted data gets created, and we pass the values of the dataBuffer and dataSize to it. */

/**
 * @brief Clean up the buffer after creating the packet.
 * */
        delete[] dataBuffer;
    }
    Address localAddress;
    m_socket->GetSockName(localAddress);
    // call to the trace sinks before the packet is actually sent,
    // so that tags added to the packet can be sent as well
    m_txTrace(p);
    if (Ipv4Address::IsMatchingType(m_peerAddress))
    {
        m_txTraceWithAddresses(
            p,
            localAddress,
            InetSocketAddress(Ipv4Address::ConvertFrom(m_peerAddress), m_peerPort));
    }
    else if (Ipv6Address::IsMatchingType(m_peerAddress))
    {
        m_txTraceWithAddresses(
            p,
            localAddress,
            Inet6SocketAddress(Ipv6Address::ConvertFrom(m_peerAddress), m_peerPort));
    }
    m_socket->Send(p);
    ++m_sent;

    if (Ipv4Address::IsMatchingType(m_peerAddress))
    {
        NS_LOG_INFO("At time " << Simulator::Now().As(Time::S) << " client sent " << m_size
                               << " bytes to " << Ipv4Address::ConvertFrom(m_peerAddress)
                               << " port " << m_peerPort);
    }
    else if (Ipv6Address::IsMatchingType(m_peerAddress))
    {
        NS_LOG_INFO("At time " << Simulator::Now().As(Time::S) << " client sent " << m_size
                               << " bytes to " << Ipv6Address::ConvertFrom(m_peerAddress)
                               << " port " << m_peerPort);
    }
    else if (InetSocketAddress::IsMatchingType(m_peerAddress))
    {
        NS_LOG_INFO(
            "At time " << Simulator::Now().As(Time::S) << " client sent " << m_size << " bytes to "
                       << InetSocketAddress::ConvertFrom(m_peerAddress).GetIpv4() << " port "
                       << InetSocketAddress::ConvertFrom(m_peerAddress).GetPort());
    }
    else if (Inet6SocketAddress::IsMatchingType(m_peerAddress))
    {
        NS_LOG_INFO(
            "At time " << Simulator::Now().As(Time::S) << " client sent " << m_size << " bytes to "
                       << Inet6SocketAddress::ConvertFrom(m_peerAddress).GetIpv6() << " port "
                       << Inet6SocketAddress::ConvertFrom(m_peerAddress).GetPort());
    }

    if (m_sent < m_count || m_count == 0)
    {
        ScheduleTransmit(m_interval);
    }
}
/**
 * @brief This function handles the process of receiving packets.
 * */
void
UdpEchoClient::HandleRead(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);
    Ptr<Packet> packet;
    Address from;
    Address localAddress;
    while ((packet = socket->RecvFrom(from)))
    {
        if (InetSocketAddress::IsMatchingType(from))
        {
            NS_LOG_INFO("At time " << Simulator::Now().As(Time::S) << " client received "
                                   << packet->GetSize() << " bytes from "
                                   << InetSocketAddress::ConvertFrom(from).GetIpv4() << " port "
                                   << InetSocketAddress::ConvertFrom(from).GetPort());
        }
        else if (Inet6SocketAddress::IsMatchingType(from))
        {
            NS_LOG_INFO("At time " << Simulator::Now().As(Time::S) << " client received "
                                   << packet->GetSize() << " bytes from "
                                   << Inet6SocketAddress::ConvertFrom(from).GetIpv6() << " port "
                                   << Inet6SocketAddress::ConvertFrom(from).GetPort());
        }
        socket->GetSockName(localAddress);
        m_rxTrace(packet);
        m_rxTraceWithAddresses(packet, from, localAddress);
    }
}

} // Namespace ns3
