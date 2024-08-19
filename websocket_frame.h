#ifndef WEBSOCKET_FRAME_H
#define WEBSOCKET_FRAME_H

#include <vector>
#include <string>

class WebsocketFrame {
public:
    void populateFromWebsocketFrameMessage(const std::vector<char>& data_in_bytes);
    std::vector<char> get_payload_data() const;

private:
    void _parse_flags(const std::vector<char>& data_in_bytes);
    void _parse_payload_length(const std::vector<char>& data_in_bytes);
    void _maybe_parse_masking_key(const std::vector<char>& data_in_bytes);
    void _parse_payload(const std::vector<char>& data_in_bytes);

    bool _fin = false;
    bool _rsv1 = false;
    bool _rsv2 = false;
    bool _rsv3 = false;
    unsigned char _opcode = 0;
    size_t _payload_length = 0;
    bool _mask = false;
    size_t _mask_key_start = 0;
    std::vector<char> _masking_key;
    std::vector<char> _payload_data;
};

#endif // WEBSOCKET_FRAME_H

