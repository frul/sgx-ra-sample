#pragma once

#define DEFAULT_CA_BUNDLE DEFAULT_CA_BUNDLE_LINUX

#include "httpparser/response.h"
#include "iasrequest.hpp"

using namespace httpparser;

using namespace std;

#include <string>

class IAS_Connection;

class Agent {
protected:
	IAS_Connection *conn;

public:
	Agent(IAS_Connection *conn_in) { conn= conn_in; }
	virtual ~Agent() { };

	virtual int initialize() { return 1; };
	virtual int request(string const &url, string const &postdata,
		Response &response) { return 0; };
};