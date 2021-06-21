#pragma once

#include <string>
#include <cstring>




void from_hexstring(unsigned char *dest, const void *vsrc, size_t len);

std::string convertUIntArray(uint8_t* bytes, size_t length);

void convertToUIntArray(const std::string& source, uint8_t *dest);

void reverse_bytes(void *dest, const void *src, size_t len);

void convertIntArrayToBytes(uint32_t* arr, size_t len, std::string& out);

void convertCharArrayToBytes(uint8_t* arr, size_t len, std::string& out);

void print_hexstring (const void *vsrc, size_t len);