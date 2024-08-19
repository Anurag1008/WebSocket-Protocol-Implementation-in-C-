#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <algorithm>

const std::string TCP_IP = "127.0.0.1";
const int TCP_PORT = 5006;
const int BUFFER_SIZE = 1024 * 1024;
const std::string WS_ENDPOINT = "/websocket";
const std::string MAGIC_WEBSOCKET_UUID_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void handle_new_connection(int main_door_socket, std::vector<int>& input_sockets);
void handle_websocket_message(int client_socket, std::vector<int>& ws_sockets);
void handle_request(int client_socket, std::vector<int>& input_sockets, std::vector<int>& ws_sockets);
void handle_ws_handshake_request(int client_socket, std::vector<int>& ws_sockets, const std::unordered_map<std::string, std::string>& headers_map);
std::string generate_sec_websocket_accept(const std::string& sec_websocket_key);
bool is_valid_ws_handshake_request(const std::string& method, const std::string& target, const std::string& http_version, const std::unordered_map<std::string, std::string>& headers_map);
std::tuple<std::string, std::string, std::string, std::unordered_map<std::string, std::string>> parse_request(const std::string& request);
void close_socket(int client_socket, std::vector<int>& input_sockets, std::vector<int>& ws_sockets);

int main() {
    int tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    int opt = 1;
    if (setsockopt(tcp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        return EXIT_FAILURE;
    }

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(TCP_IP.c_str());
    address.sin_port = htons(TCP_PORT);

    if (bind(tcp_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return EXIT_FAILURE;
    }

    if (listen(tcp_socket, 1) < 0) {
        perror("Listen failed");
        return EXIT_FAILURE;
    }

    std::cout << "Listening on port: " << TCP_PORT << std::endl;

    std::vector<int> input_sockets{tcp_socket};
    std::vector<int> ws_sockets;

    while (true) {
        fd_set read_fds;
        FD_ZERO(&read_fds);

        int max_fd = tcp_socket;
        for (int fd : input_sockets) {
            FD_SET(fd, &read_fds);
            if (fd > max_fd) max_fd = fd;
        }

        timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        if (select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout) < 0) {
            perror("Select error");
            return EXIT_FAILURE;
        }

        for (int fd : input_sockets) {
            if (FD_ISSET(fd, &read_fds)) {
                if (fd == tcp_socket) {
                    handle_new_connection(tcp_socket, input_sockets);
                } else if (std::find(ws_sockets.begin(), ws_sockets.end(), fd) != ws_sockets.end()) {
                    handle_websocket_message(fd, ws_sockets);
                } else {
                    handle_request(fd, input_sockets, ws_sockets);
                }
            }
        }
    }

    return 0;
}

void handle_new_connection(int main_door_socket, std::vector<int>& input_sockets) {
    sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_socket = accept(main_door_socket, (struct sockaddr*)&client_addr, &addr_len);
    if (client_socket < 0) {
        perror("Accept failed");
        return;
    }
    std::cout << "New socket " << client_socket << " from address: " << inet_ntoa(client_addr.sin_addr) << std::endl;
    input_sockets.push_back(client_socket);
}

void handle_websocket_message(int client_socket, std::vector<int>& ws_sockets) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        close_socket(client_socket, ws_sockets, ws_sockets);
        return;
    }

    // Process the WebSocket frame
    // Implement WebSocket frame processing here

    std::cout << "Received WebSocket message" << std::endl;
}

void handle_request(int client_socket, std::vector<int>& input_sockets, std::vector<int>& ws_sockets) {
    char buffer[BUFFER_SIZE];
    std::string message;
    
    while (true) {
        int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            close_socket(client_socket, input_sockets, ws_sockets);
            return;
        }

        message.append(buffer, bytes_received);
        if (message.find("\r\n\r\n") != std::string::npos) {
            break;
        }
    }

    std::cout << "Received message:" << std::endl;
    std::cout << message << std::endl;

    auto [method, target, http_version, headers_map] = parse_request(message);

    std::cout << "method, target, http_version: " << method << ", " << target << ", " << http_version << std::endl;
    std::cout << "headers:" << std::endl;
    for (const auto& [header, value] : headers_map) {
        std::cout << header << ": " << value << std::endl;
    }

    if (target == WS_ENDPOINT) {
        std::cout << "Request to WS endpoint!" << std::endl;
        if (is_valid_ws_handshake_request(method, target, http_version, headers_map)) {
            handle_ws_handshake_request(client_socket, ws_sockets, headers_map);
        } else {
            send(client_socket, "HTTP/1.1 400 Bad Request\r\n\r\n", 29, 0);
            close_socket(client_socket, input_sockets, ws_sockets);
        }
        return;
    }

    const std::string default_http_response =
        "<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\r\n"
        "<TITLE>200 OK</TITLE></HEAD><BODY>\r\n"
        "<H1>200 OK</H1>\r\n"
        "Welcome to the default.\r\n"
        "</BODY></HTML>\r\n\r\n";

    send(client_socket, ("HTTP/1.1 200 OK\r\n\r\n" + default_http_response).c_str(), default_http_response.size() + 17, 0);
    close_socket(client_socket, input_sockets, ws_sockets);
}

void handle_ws_handshake_request(int client_socket, std::vector<int>& ws_sockets, const std::unordered_map<std::string, std::string>& headers_map) {
    ws_sockets.push_back(client_socket);
    std::string sec_websocket_accept = generate_sec_websocket_accept(headers_map.at("sec-websocket-key"));

    std::string websocket_response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + sec_websocket_accept + "\r\n\r\n";

    std::cout << "\nresponse:\n" << websocket_response << std::endl;

    send(client_socket, websocket_response.c_str(), websocket_response.size(), 0);
}

std::string generate_sec_websocket_accept(const std::string& sec_websocket_key) {
    std::string combined = sec_websocket_key + MAGIC_WEBSOCKET_UUID_STRING;
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined.c_str()), combined.size(), hash);

    char encoded[EVP_ENCODE_LENGTH(SHA_DIGEST_LENGTH)];
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded), hash, SHA_DIGEST_LENGTH);

    return std::string(encoded);
}

bool is_valid_ws_handshake_request(const std::string& method, const std::string& target, const std::string& http_version, const std::unordered_map<std::string, std::string>& headers_map) {
    bool is_get = method == "GET";
    float http_version_number = std::stof(http_version.substr(5));
    bool http_version_enough = http_version_number >= 1.1;
    bool headers_valid =
        headers_map.count("upgrade") && headers_map.at("upgrade") == "websocket" &&
        headers_map.count("connection") && headers_map.at("connection") == "Upgrade" &&
        headers_map.count("sec-websocket-key");

    return is_get && http_version_enough && headers_valid;
}

std::tuple<std::string, std::string, std::string, std::unordered_map<std::string, std::string>> parse_request(const std::string& request) {
    std::unordered_map<std::string, std::string> headers_map;
    size_t pos = request.find("\r\n\r\n");
    std::string headers = request.substr(0, pos);
    std::string body = request.substr(pos + 4);

    size_t first_line_end = headers.find("\r\n");
    std::string first_line = headers.substr(0, first_line_end);
    std::string method = first_line.substr(0, first_line.find(' '));
    std::string target = first_line.substr(first_line.find(' ') + 1, first_line.find(' ', first_line.find(' ') + 1) - first_line.find(' ') - 1);
    std::string http_version = first_line.substr(first_line.find_last_of(' ') + 1);

    size_t pos_start = headers.find("\r\n") + 2;
    while (pos_start < headers.size()) {
        size_t pos_end = headers.find("\r\n", pos_start);
        std::string header_line = headers.substr(pos_start, pos_end - pos_start);
        size_t colon_pos = header_line.find(':');
        if (colon_pos != std::string::npos) {
            std::string header_name = header_line.substr(0, colon_pos);
            std::string header_value = header_line.substr(colon_pos + 2);
            headers_map[header_name] = header_value;
        }
        pos_start = pos_end + 2;
    }

    return std::make_tuple(method, target, http_version, headers_map);
}

void close_socket(int client_socket, std::vector<int>& input_sockets, std::vector<int>& ws_sockets) {
    std::cout << "closing socket" << std::endl;
    auto it = std::find(ws_sockets.begin(), ws_sockets.end(), client_socket);
    if (it != ws_sockets.end()) {
        ws_sockets.erase(it);
    }
    it = std::find(input_sockets.begin(), input_sockets.end(), client_socket);
    if (it != input_sockets.end()) {
        input_sockets.erase(it);
    }
    close(client_socket);
}

