#define AGENT_WGET

#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include "crypto_functions.hpp"
#include "agent.hpp"
#include "agent_wget.hpp"
#include "agent_curl.hpp"
#include "iasrequest.hpp"
#include "httpparser/response.h"
#include "base64.hpp"

using namespace std;
using namespace httpparser;

#include <string>
#include <exception>

static char debug = 0;
static char verbose = 0;
static std::string 	c_agent_name= "libcurl";

static string ias_servers[2]= {
    IAS_SERVER_DEVELOPMENT_HOST,
    IAS_SERVER_PRODUCTION_HOST
};

static string url_decode(string str);

void ias_list_agents (FILE *fp)
{
	fprintf(fp, "Available user agents:\n");
#ifdef AGENT_WGET
	fprintf(fp, "%s\n", AgentWget::name.c_str());
#endif
#ifdef AGENT_WINHTTP
	fprintf(fp, "%s\n", AgentWinHttp::name.c_str());
#endif
}

IAS_Connection::IAS_Connection(int server_idx, uint32_t flags, char *priSubscriptionKey, char *secSubscriptionKey)
{
	c_server= ias_servers[server_idx];
	c_flags= flags;
	c_server_port= IAS_PORT;
	c_proxy_mode= IAS_PROXY_AUTO;
	c_agent= NULL;
	c_proxy_port= 80;
	c_store= NULL;
	setSubscriptionKey(SubscriptionKeyID::Primary, "b94ae2aef38c48e98c4b98e06c531bf6"); 
	setSubscriptionKey(SubscriptionKeyID::Secondary, "83548b6ae777400d8aa6586cadbf34f8"); 
}

IAS_Connection::~IAS_Connection()
{
}

int IAS_Connection::agent(const char *agent_name)
{
#ifdef AGENT_WGET
	if ( AgentWget::name == agent_name ) {
		c_agent_name= agent_name;
		return 1;
	}
#endif
#ifdef AGENT_WINHTTP
	if (AgentWinHttp::name == agent_name) {
		c_agent_name = agent_name;
		return 1;
	}
#endif

	return 0;
}

int IAS_Connection::proxy(const char *server, uint16_t port)
{
	int rv= 1;
	try {
		c_proxy_server= server;
	}
	catch (...) {
		rv= 0;
	}
	c_proxy_port= port;

	c_proxy_mode = IAS_PROXY_FORCE;

	return rv;
}

string IAS_Connection::proxy_url()
{
	string proxy_url;

	if ( c_proxy_server == "" ) return "";

	proxy_url= "http://" + c_proxy_server;

	if ( c_proxy_port != 80 ) {
		proxy_url+= ":";
		proxy_url+= to_string(c_proxy_port);
	}

	return proxy_url;
}

// Encrypt the subscription key while its stored in memory
int IAS_Connection::setSubscriptionKey(SubscriptionKeyID id, const char * subscriptionKeyPlainText)
{
	memset(subscription_key_enc[id], 0, sizeof(subscription_key_enc[id]));
	memset(subscription_key_xor[id], 0, sizeof(subscription_key_xor[id]));

	if (subscriptionKeyPlainText == NULL || (strlen(subscriptionKeyPlainText) != IAS_SUBSCRIPTION_KEY_SIZE) ||
	(id == SubscriptionKeyID::Last))
	{
		printf("Error Setting subscriptionKey\n");
		return 0;
	}

    // Create Random one time pad
    RAND_bytes((unsigned char *)subscription_key_xor[id], (int) sizeof(subscription_key_xor[id]));

    // XOR Subscription Key with One Time Pad to create an encrypted key
    for (int i= 0; i < IAS_SUBSCRIPTION_KEY_SIZE; i++)
                subscription_key_enc[id][i] = (unsigned char) subscriptionKeyPlainText[i] ^ subscription_key_xor[id][i];


    // zero the original subscription key in memory
    //memset(subscriptionKeyPlainText, 0, IAS_SUBSCRIPTION_KEY_SIZE);

    return 1;
}

// Decrypt then return the subscription key
string IAS_Connection::getSubscriptionKey()
{
	char keyBuff[IAS_SUBSCRIPTION_KEY_SIZE+1];
	memset(keyBuff, 0, IAS_SUBSCRIPTION_KEY_SIZE+1);

        for ( int i = 0; i < IAS_SUBSCRIPTION_KEY_SIZE; i++ )
                 keyBuff[i] = (subscription_key_enc[currentKeyID][i] ^ subscription_key_xor[currentKeyID][i]);

	string subscriptionKeyBuff(keyBuff);

    return subscriptionKeyBuff;
}

string IAS_Connection::base_url()
{
	string url= "https://" + c_server;

	if ( c_server_port != 443 ) {
		url+= ":";
		url+= to_string(c_server_port);
	}

	url+= "/attestation/v";

	return url;
}

// Reuse the existing agent or get a new one.

Agent *IAS_Connection::agent()
{
	if ( c_agent == NULL ) return this->new_agent();
	return c_agent;
}

// Get a new agent (and discard the old one if there was one)

Agent *IAS_Connection::new_agent()
{
	Agent *newagent= NULL;

	// If we've requested a specific agent, use that one

	if ( c_agent_name.length() ) {
#ifdef AGENT_WGET
		if ( c_agent_name == AgentCurl::name ) {
			try {
				newagent= (Agent *) new AgentCurl(this);
			}
			catch (...) {
				if ( newagent != NULL ) delete newagent;
				return NULL;
			}
			return newagent;
		} else {
			try {
				newagent= (Agent *) new AgentWget(this);
			}
			catch (...) {
				if ( newagent != NULL ) delete newagent;
				return NULL;
			}
			return newagent;
		}
#endif
#ifdef AGENT_WINHTTP
		if (c_agent_name == AgentWinHttp::name) {
			try {
				newagent = (Agent *) new AgentWinHttp(this);
			}
			catch (...) {
				if ( newagent != NULL ) delete newagent;
				return NULL;
			}
			return newagent;
		}
#endif
	} else {
		// Otherwise, take the first available using this hardcoded
		// order of preference.
#ifdef AGENT_WGET
		if ( newagent == NULL ) {
			if ( debug ) printf("+++ Trying agent_wget\n");
			try {
				newagent= (Agent *) new AgentCurl(this);
			}
			catch (...) { 
				if ( newagent != NULL ) delete newagent;
				newagent= NULL;
			}
		}
#endif
#ifdef AGENT_WINHTTP
		if (newagent == NULL) {
			if (debug) printf("+++ Trying agent_winhttp\n");
			try {
				newagent = (Agent *) new AgentWinHttp(this);
			}
			catch (...) { newagent = NULL; }
		}
#endif
	}

	if ( newagent == NULL ) return NULL;

	if ( newagent->initialize() == 0 ) {
		delete newagent;
		return NULL;
	}

	c_agent= newagent;
	return c_agent;
}

IAS_Request::IAS_Request(IAS_Connection *conn, uint16_t version)
{
	r_conn= conn;
	r_api_version= version;
}

IAS_Request::~IAS_Request()
{
}

ias_error_t IAS_Request::sigrl(uint32_t gid, string &sigrl)
{
	Response response;
	char sgid[9];
	string url= r_conn->base_url();
	Agent *agent= r_conn->new_agent();

	if ( agent == NULL ) {
		printf("Could not allocate agent object");
		return IAS_QUERY_FAILED;
	}

	snprintf(sgid, 9, "%08x", gid);

	url+= to_string(r_api_version);
	url+= "/sigrl/";
	url+= sgid;


	if ( agent->request(url, "", response) ) {

		if ( response.statusCode == IAS_OK ) {
			sigrl= response.content_string();
		} 

	} else {
		delete agent;
		return IAS_QUERY_FAILED;
	}

	delete agent;
	return response.statusCode;
}

ias_error_t IAS_Request::report(map<string,string> &payload, string &content,
	vector<string> &messages)
{
	Response response;
	map<string,string>::iterator imap;
	string url= r_conn->base_url();
	string certchain;
	string body= "{\n";
	size_t cstart, cend, count, i;
	vector<X509 *> certvec;
	X509 **certar;
	X509 *sign_cert;
	STACK_OF(X509) *stack;
	string sigstr, header;
	size_t sigsz;
	ias_error_t status;
	int rv;
	unsigned char *sig= NULL;
	EVP_PKEY *pkey= NULL;
	Agent *agent= r_conn->new_agent();
	
	if ( agent == NULL ) {
		printf("Could not allocate agent object");
		return IAS_QUERY_FAILED;
	}

	try {
		for (imap= payload.begin(); imap!= payload.end(); ++imap) {
			if ( imap != payload.begin() ) {
				body.append(",\n");
			}
			body.append("\"");
			body.append(imap->first);
			body.append("\":\"");
			body.append(imap->second);
			body.append("\"");
		}
		body.append("\n}");

		url+= to_string(r_api_version);
		url+= "/report";
	}
	catch (...) {
		delete agent;
		return IAS_QUERY_FAILED;
	}


	if (!agent->request(url, body, response) ) {

		delete agent;
		return IAS_QUERY_FAILED;
	}

	if ( response.statusCode != IAS_OK ) {
		delete agent;
		return response.statusCode;
	}

	/*
	 * The response body has the attestation report. The headers have
	 * a signature of the report, and the public signing certificate.
	 * We need to:
	 *
	 * 1) Verify the certificate chain, to ensure it's issued by the
	 *    Intel CA (passed with the -A option).
	 *
	 * 2) Extract the public key from the signing cert, and verify
	 *    the signature.
	 */

	// Get the certificate chain from the headers 

	certchain= response.headers_as_string("X-IASReport-Signing-Certificate");
	if ( certchain == "" ) {
		printf("Header X-IASReport-Signing-Certificate not found\n");
		delete agent;
		return IAS_BAD_CERTIFICATE;
	}

	// URL decode
	try {
		certchain= url_decode(certchain);
	}
	catch (...) {
		printf("invalid URL encoding in header X-IASReport-Signing-Certificate\n");
		delete agent;
		return IAS_BAD_CERTIFICATE;
	}

	// Build the cert stack. Find the positions in the string where we
	// have a BEGIN block.

	cstart= cend= 0;
	while (cend != string::npos ) {
		X509 *cert;
		size_t len;

		cend= certchain.find("-----BEGIN", cstart+1);
		len= ( (cend == string::npos) ? certchain.length() : cend )-cstart;


		if ( ! cert_load(&cert, certchain.substr(cstart, len).c_str()) ) {
			crypto_perror("cert_load");
			delete agent;
			return IAS_BAD_CERTIFICATE;
		}

		certvec.push_back(cert);
		cstart= cend;
	}

	count= certvec.size();
	if ( debug ) printf( "+++ Found %lu certificates in chain\n", count);

	certar= (X509**) malloc(sizeof(X509 *)*(count+1));
	if ( certar == 0 ) {
		perror("malloc");
		delete agent;
		return IAS_INTERNAL_ERROR;
	}
	for (i= 0; i< count; ++i) certar[i]= certvec[i];
	certar[count]= NULL;

	// Create a STACK_OF(X509) stack from our certs

	stack= cert_stack_build(certar);
	if ( stack == NULL ) {
		crypto_perror("cert_stack_build");
		status= IAS_INTERNAL_ERROR;
		goto cleanup;
	}

	// Now verify the signing certificate

	rv= cert_verify(this->conn()->cert_store(), stack);

	if ( ! rv ) {
		crypto_perror("cert_stack_build");
		printf("certificate verification failure\n");
		status= IAS_BAD_CERTIFICATE;
		goto cleanup;
	} else {
		if ( debug ) printf("+++ certificate chain verified\n");
	}

	// The signing cert is valid, so extract and verify the signature

	sigstr= response.headers_as_string("X-IASReport-Signature");
	if ( sigstr == "" ) {
		printf("Header X-IASReport-Signature not found\n");
		status= IAS_BAD_SIGNATURE;
		goto cleanup;
	}

	sig= (unsigned char *) base64_decode(sigstr.c_str(), &sigsz);
	if ( sig == NULL ) {
		printf("Could not decode signature\n");
		status= IAS_BAD_SIGNATURE;
		goto cleanup;
	}


	sign_cert= certvec[0]; /* The first cert in the list */

	/*
	 * The report body is SHA256 signed with the private key of the
	 * signing cert.  Extract the public key from the certificate and
	 * verify the signature.
	 */

	if ( debug ) printf("+++ Extracting public key from signing cert\n");
	pkey= X509_get_pubkey(sign_cert);
	if ( pkey == NULL ) {
		printf("Could not extract public key from certificate\n");
		status= IAS_INTERNAL_ERROR;
		goto cleanup;
	}

	content= response.content_string();

	if ( ! sha256_verify((const unsigned char *) content.c_str(),
		content.length(), sig, sigsz, pkey, &rv) ) {

		crypto_perror("sha256_verify");
		printf("Could not validate signature\n");
		status= IAS_BAD_SIGNATURE;
	} else {
		if ( rv ) {
			status= IAS_OK;
		} else {
			status= IAS_BAD_SIGNATURE;
		}
	}

	if ( r_api_version == 3 ) {
		/*
	 	 * Check for advisory headers in a v3 response. In v4 these
		 * are part of the report.
	 	 */
	
		header= response.headers_as_string("Advisory-URL");
		if ( header.length() ) messages.push_back(header);

		header= response.headers_as_string("Advisory-IDs");
		if ( header.length() ) messages.push_back(header);
	}

cleanup:
	if ( pkey != NULL ) EVP_PKEY_free(pkey);
	cert_stack_free(stack);
	free(certar);
	for (i= 0; i<count; ++i) X509_free(certvec[i]);
	free(sig);
	delete agent;

	return status;
}

// A simple URL decoder 

static string url_decode(string str)
{
	string decoded;
	size_t i;
	size_t len= str.length();

	for (i= 0; i< len; ++i) {
		if ( str[i] == '+' ) decoded+= ' ';
		else if ( str[i] == '%' ) {
			char *e= NULL;
			unsigned long int v;

			// Have a % but run out of characters in the string

			if ( i+3 > len ) throw std::length_error("premature end of string");

			v= strtoul(str.substr(i+1, 2).c_str(), &e, 16);

			// Have %hh but hh is not a valid hex code.
			if ( *e ) throw std::out_of_range("invalid encoding");

			decoded+= static_cast<char>(v);
			i+= 2;
		} else decoded+= str[i];
	}

	return decoded;
}

