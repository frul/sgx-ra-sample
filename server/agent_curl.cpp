/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#include <sys/types.h>
#include <curl/curl.h>
#include "httpparser/response.h"
#include "httpparser/httpresponseparser.h"
#include "agent_curl.hpp"
#include "agent.hpp"
#include "iasrequest.hpp"
#include <iostream>

using namespace std;
using namespace httpparser;

#include <string>

static size_t _header_callback(char *ptr, size_t sz, size_t n, void *data);
static size_t _write_callback(char *ptr, size_t sz, size_t n, void *data);
static size_t _read_callback(char *buffer, size_t size, size_t nitems, 
	void *instream);

string AgentCurl::name= "libcurl";

static int debug = 0;

struct data {
  char trace_ascii; /* 1 or 0 */
};
 
static
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          char nohex)
{
  size_t i;
  size_t c;
 
  unsigned int width = 0x10;
 
  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;
 
  fprintf(stream, "%s, %10.10lu bytes (0x%8.8lx)\n",
          text, (unsigned long)size, (unsigned long)size);
 
  for(i = 0; i<size; i += width) {
 
    fprintf(stream, "%4.4lx: ", (unsigned long)i);
 
    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stream, "%02x ", ptr[i + c]);
        else
          fputs("   ", stream);
    }
 
    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stream, "%c",
              (ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stream); /* newline */
  }
  fflush(stream);
}
 
static
int my_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  struct data *config = (struct data *)userp;
  const char *text;
  (void)handle; /* prevent compiler warning */
 
  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== Info: %s", data);
    /* FALLTHROUGH */
  default: /* in case a new one is introduced to shock us */
    return 0;
 
  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  }
 
  dump(text, stderr, (unsigned char *)data, size, config->trace_ascii);
  return 0;
}


AgentCurl::AgentCurl (IAS_Connection *conn_in) : Agent(conn_in)
{
	curl= NULL;
	sresponse= "";
	header_len= header_pos= 0;
	flag_eoh= 0;
}

AgentCurl::~AgentCurl ()
{
	curl_easy_cleanup(curl);
}

int AgentCurl::initialize ()
{
	size_t pwlen;
	char *passwd= NULL;

	// Calls curl_global_init() if it hasn't been already. This is
	// not a thread-safe approach, but we are single-threaded.

	curl= curl_easy_init();
	if ( curl == NULL ) return 0;

	if ( debug ) {
		if ( curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L) != CURLE_OK )
			return 0;
	}

	// General client configuration options
	//------------------------------------------------------------

	// HTTPS only
	if ( curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS) !=
		CURLE_OK ) return 0;

	// Include the server response headers
	if ( curl_easy_setopt(curl, CURLOPT_HEADER, 1L) != CURLE_OK ) return 0;

#ifdef CURL_OPT_SUPPRESS_CONNECT_HEADERS
	// Suppress the proxy CONNECT headers.
	if ( curl_easy_setopt(curl, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L) !=
		CURLE_OK ) return 0;
#else
	// Sigh. Our version of libcurl is too old so we need to detect
	// proxy headers by hand.

	if ( curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, _header_callback)
		 != CURLE_OK) return 0;

	if ( curl_easy_setopt(curl, CURLOPT_HEADERDATA, this) != CURLE_OK)
		return 0;
#endif

	curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);

	// Configure proxy
	//------------------------------------------------------------

	if ( conn->proxy_mode() == IAS_PROXY_NONE ) {
		// Setting this to an empty string will force the proxy off
		// regardless of any proxy environment vars.

		if ( curl_easy_setopt(curl, CURLOPT_PROXY, "") != CURLE_OK )
			return 0;

	} else if ( conn->proxy_mode() == IAS_PROXY_FORCE ) {
		string proxy_url= conn->proxy_url();

		// First, are we overriding the proxy environment vars?

		if ( proxy_url != "" ) {
			if ( curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url.c_str())
				 != CURLE_OK )

				return 0;
		}

		// Now force the use of the proxy by overriding no_proxy
		// environment vars.

		if ( curl_easy_setopt(curl, CURLOPT_NOPROXY, "") != CURLE_OK )
			return 0;
	}

	// Specify your certificate stores

	if ( curl_easy_setopt(curl, CURLOPT_CAINFO, conn->ca_bundle().c_str())
		!= CURLE_OK ) return 0;

	// Set the write callback.

	if ( curl_easy_setopt(curl, CURLOPT_WRITEDATA, this) != CURLE_OK )
		return 0;

	if ( curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _write_callback) 
		!= CURLE_OK ) return 0;

	return 1;
}


int AgentCurl::request(string const &url, string const &postdata,
	Response &response)
{
	sresponse= "";
	HttpResponseParser parser;
	HttpResponseParser::ParseResult result;
	const char *bp;

	header_len= header_pos= 0;
	flag_eoh= 0;
	curl_slist *slist= NULL;

	// construct then add the Ocp-Apim-Subscription-Key subscription key header
	string subscriptionKeyHeader = "Ocp-Apim-Subscription-Key: ";
	subscriptionKeyHeader.append(conn->getSubscriptionKey());

    if ( (slist = curl_slist_append(slist, subscriptionKeyHeader.c_str())) == NULL )
		return 0;

	if ( postdata != "" ) {

		// Set our POST specific headers
		slist = curl_slist_append(slist, "Accept: application/json");
		slist = curl_slist_append(slist, "Content-Type: application/json");
		slist = curl_slist_append(slist, "charset: utf-8");
		

		if ( (slist= curl_slist_append(slist, "Expect:")) == NULL )
			return 0;

		// Set our method to POST and send the length
		bp= postdata.c_str();

		if ( curl_easy_setopt(curl, CURLOPT_POSTFIELDS, 
			postdata.c_str()) != CURLE_OK ) return 0;

	} 

	if ( curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist)
		!= CURLE_OK ) return 0;

	if ( curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) != CURLE_OK )
		return 0;

	if (debug) {
		struct data config;
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
		curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &config);
		/* the DEBUGFUNCTION has no effect until we enable VERBOSE */
    	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	}
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);

	if ( curl_easy_perform(curl) != 0 ) {
		return 0;
	}

	if (slist != NULL) {
		curl_slist_free_all(slist);
		slist = NULL;
	}

	result= parser.parse(response, sresponse.substr(header_pos).c_str(),
		sresponse.c_str()+sresponse.length());

    return ( result == HttpResponseParser::ParsingCompleted );
}

size_t AgentCurl::header_callback(char *ptr, size_t sz, size_t n)
{
	size_t len= sz*n;
	string header;
	size_t idx;

	// Look for a blank header that occurs in the middle of the
	// headers: that's the separator between the proxy and server
	// headers. We want the last header block.

	header.assign(ptr, len);
	// Find where newline chars begin
	idx= header.find_first_of("\n\r");

	if ( flag_eoh ) {
		if ( idx != 0 )	{
			// We got a non-blank header line after receiving the
			// end of a header block, so we have started a new
			// header block.

			header_pos= header_len;
			flag_eoh= 0;
		} 
	} else {
		// If we have a blank line, we reached the end of a header
		// block.
		if ( idx == 0 ) flag_eoh= 1;
	}

	header_len+= len;

	return len;
}

size_t AgentCurl::write_callback(char *ptr, size_t sz, size_t n)
{
	size_t len= sz*n;
	sresponse.append(ptr, len);
	return len;
}

static size_t _header_callback(char *ptr, size_t sz, size_t n, void *data)
{
	AgentCurl *agent= (AgentCurl *) data;

	return agent->header_callback(ptr, sz, n);
}

static size_t _write_callback(char *ptr, size_t sz, size_t n, void *data)
{
	AgentCurl *agent= (AgentCurl *) data;

	return agent->write_callback(ptr, sz, n);
}

static size_t _read_callback(char *buffer, size_t sz, size_t n, void *instream)
{
	// We need to write no more than sz*n bytes into "buffer", so we need
	// to keep track of where we are in our internal postdata buffer.
	char **bp= (char **) instream;
	size_t len= sz*n;
	size_t slen= strlen(*bp);

	if ( !slen ) return 0;

	len= ( slen < len ) ? slen : len;

	memcpy(buffer, *bp, len);
	for (slen= 0; slen< len; ++slen) fputc(buffer[slen], stderr);
	*bp+= len;

	return len;
}

