#ifndef TOR_PACKET_H
#define TOR_PACKET_H

#include <string>
#include <vector>
#include <openssl/sha.h>

// Define packet types
enum PacketType {
    DATA_PACKET = 1,
    CONTROL_PACKET = 2
};

// Enhanced packet structure for TOR with additional fields
struct TORPacket {
    uint32_t sequenceNumber;
    std::string originalData;
    std::string data;
    uint32_t currentLayer;
    uint32_t numLayers;
    double timestamp;
    uint32_t hopCount;
    std::string sourceNode;
    std::string destinationNode;
    uint32_t circuitId;
    bool isControl;
    uint32_t packetSize;
    uint16_t packetType;
    uint16_t protocol;
    std::vector<uint32_t> route; // Add route field
    std::string checksum; // Add checksum field

    // Methods for encrypting and decrypting packet data
    void EncryptPacket();
    void DecryptPacket();
    void CalculateChecksum();
    bool VerifyChecksum();
};

#endif
