#include "utils.hpp"

void from_hexstring(unsigned char *dest, const void *vsrc, size_t len)
{
	size_t i;
	const char *src= (const char *) vsrc;
	for (i= 0; i<len; ++i) {
		unsigned int v;
		if ( sscanf(&src[i*2], "%2xhh", &v) == 0 ) return;
		dest[i]= (unsigned char) v;
	}
}

std::string convertUIntArray(uint8_t* bytes, size_t length) {
    return std::string(bytes, bytes + length);
}

void reverse_bytes(void *dest, const void *src, size_t len)
{
	size_t i;
	char *sp= (char *)src;

	if ( len < 2 ) return;

	if ( src == dest ) {
		size_t j;

		for (i= 0, j= len-1; i<j; ++i, --j) {
			char t= sp[j];
			sp[j]= sp[i];
			sp[i]= t;
		}
	} else {
		char *dp= (char *) dest + len - 1;
		for (i= 0; i< len; ++i, ++sp, --dp) *dp= *sp;
	}
}

void convertToUIntArray(const std::string& source, uint8_t *dest) {
	strcpy((char *)dest, source.c_str());
}

void convertIntArrayToBytes(uint32_t* arr, size_t len, std::string& out) {
	char* intermediate = static_cast<char*>(static_cast<void*>(arr));
	std::string result(intermediate, intermediate + len * 4);
	out = result;
}

void convertCharArrayToBytes(uint8_t* arr, size_t len, std::string& out) {
	char* intermediate = static_cast<char*>(static_cast<void*>(arr));
	std::string result(intermediate, intermediate + len);
	out = result;
}

void print_hexstring (const void *vsrc, size_t len)
{
	const unsigned char *sp= (const unsigned char *) vsrc;
	size_t i;
	for(i= 0; i< len; ++i) {
		printf("%02x", sp[i]);
	}
	printf("\n");
}