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
    double timestamp;
    uint32_t hopCount;
    std::string sourceNode;
    std::string destinationNode;
    uint32_t circuitId;
    bool isControl;
    uint16_t protocol; // Add protocol field
    uint32_t packetSize;
    uint16_t packetType;
    std::vector<uint32_t> route; // Add route field
    uint32_t currentLayer;
    uint32_t numLayers;
    std::string checksum; // Add checksum field

    // Methods for encrypting and decrypting packet data
    bool EncryptPacket(uint32_t layer);
    bool DecryptPacket(uint32_t layer);
    void CalculateChecksum();
    bool VerifyChecksum();
};

#endif
