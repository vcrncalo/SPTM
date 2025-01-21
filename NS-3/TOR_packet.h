#ifndef TOR_PACKET_H
#define TOR_PACKET_H

#include <string>
#include <vector>

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
    uint16_t protocol; // Add protocol field
    std::vector<uint32_t> route; // Add route field

    // Methods for encrypting and decrypting packet data
    void EncryptPacket(const std::string& key);
    void DecryptPacket(const std::string& key);
};

#endif
