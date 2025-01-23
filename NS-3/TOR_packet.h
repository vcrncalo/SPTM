#ifndef TOR_PACKET_H
#define TOR_PACKET_H

#include <string>
#include <vector>
#include <openssl/sha.h>

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
    uint16_t protocol; // Add protocol field
    std::vector<uint32_t> route; // Add route field
    std::string checksum; // Add checksum field

    // Methods for encrypting and decrypting packet data
    void EncryptPacket(const std::string& key);
    void DecryptPacket(const std::string& key);
    void CalculateChecksum();
    bool VerifyChecksum();
};

#endif
