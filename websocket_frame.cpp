#include <iostream>
#include <vector>
#include <cstring>
#include "websocket_frame.h"

const std::string MAGIC_WEBSOCKET_UUID_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void WebsocketFrame::populateFromWebsocketFrameMessage(const std::vector<char>& data_in_bytes) {
    _parse_flags(data_in_bytes);
    _parse_payload_length(data_in_bytes);
    _maybe_parse_masking_key(data_in_bytes);
    _parse_payload(data_in_bytes);
}

void WebsocketFrame::_parse_flags(const std::vector<char>& data_in_bytes) {
    unsigned char first_byte = data_in_bytes[0];
    _fin = (first_byte & 0b10000000) != 0;
    _rsv1 = (first_byte & 0b01000000) != 0;
    _rsv2 = (first_byte & 0b00100000) != 0;
    _rsv3 = (first_byte & 0b00010000) != 0;
    _opcode = first_byte & 0b00001111;

    unsigned char second_byte = data_in_bytes[1];
    _mask = (second_byte & 0b10000000) != 0;
}

void WebsocketFrame::_parse_payload_length(const std::vector<char>& data_in_bytes) {
    unsigned char payload_length = data_in_bytes[1] & 0b01111111;
    size_t mask_key_start = 2;

    if (payload_length == 126) {
        payload_length = (data_in_bytes[2] << 8) | data_in_bytes[3];
        mask_key_start = 4;
    } else if (payload_length == 127) {
        payload_length = 0;
        for (int i = 0; i < 8; ++i) {
            payload_length = (payload_length << 8) | static_cast<unsigned char>(data_in_bytes[2 + i]);
        }
        mask_key_start = 10;
    }
    _payload_length = payload_length;
    _mask_key_start = mask_key_start;
}

void WebsocketFrame::_maybe_parse_masking_key(const std::vector<char>& data_in_bytes) {
    if (!_mask) return;
    _masking_key.assign(data_in_bytes.begin() + _mask_key_start, data_in_bytes.begin() + _mask_key_start + 4);
}

void WebsocketFrame::_parse_payload(const std::vector<char>& data_in_bytes) {
    std::vector<char> payload_data;

    if (_payload_length == 0) return;

    size_t payload_start = _mask ? _mask_key_start + 4 : _mask_key_start;
    std::vector<char> encoded_payload(data_in_bytes.begin() + payload_start, data_in_bytes.begin() + payload_start + _payload_length);

    if (_mask) {
        payload_data.resize(encoded_payload.size());
        for (size_t i = 0; i < encoded_payload.size(); ++i) {
            payload_data[i] = encoded_payload[i] ^ _masking_key[i % 4];
        }
    } else {
        payload_data = std::move(encoded_payload);
    }

    _payload_data = std::move(payload_data);
}

std::vector<char> WebsocketFrame::get_payload_data() const {
    return _payload_data;
}

