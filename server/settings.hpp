#pragma once

#include <string>

struct ServerSettings {
    std::string ip;
    std::string port;
    std::string public_key;
    std::string spid;
    std::string primary_subscription_key;
    std::string secondary_subscription_key;
    std::string ias_key_file;
};

ServerSettings ReadServerSettings();