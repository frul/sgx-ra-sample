#pragma once

#include <string>

struct Settings {
    std::string ip;
    std::string port;
    std::string public_key;
};

Settings ReadSettings();