#pragma once

#include "../common/sgx_declarations.hpp"

struct ConnectionAttributes {
    GroupId gid;
    unsigned char g_a[64];
    unsigned char g_b[64];
    unsigned char kdk[16];
    unsigned char smk[16];
    unsigned char sk[16];
    unsigned char mk[16];
    unsigned char vk[16];
    bool trusted = false;
};