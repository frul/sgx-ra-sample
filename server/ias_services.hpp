#pragma once

#include "iasrequest.hpp"
#include "base64.hpp"
#include "../common/utils.hpp"
#include "json.hpp"

using namespace json;

std::set<std::string> allowed_advisories {"INTEL-SA-00334"};

int get_sigrl (IAS_Connection *ias, GroupId gid,
	char **sig_rl, uint32_t *sig_rl_size)
{
	IAS_Request *req= NULL;
	int oops= 1;
	string sigrlstr;
	bool debug = false;

	try {
		oops= 0;
		req= new IAS_Request(ias, (uint16_t)IAS_API_DEF_VERSION);
	}
	catch (...) {
		oops = 1;
	}

	if (oops) {
		printf("Exception while creating IAS request object\n");
		delete req;
		return 0;
	}
 
    ias_error_t ret = IAS_OK;

	while (1) {

		ret =  req->sigrl(*(uint32_t *) gid, sigrlstr);
		
		if (debug) {
			printf("+++ RET = %u\n", ret);
			printf("+++ SubscriptionKeyID = %d\n",(int)ias->getSubscriptionKeyID());
		}
            
	
		if ( ret == IAS_UNAUTHORIZED && (ias->getSubscriptionKeyID() == IAS_Connection::SubscriptionKeyID::Primary))
		{

		    
				printf("+++ IAS Primary Subscription Key failed with IAS_UNAUTHORIZED\n");
				printf("+++ Retrying with IAS Secondary Subscription Key\n");
			

			// Retry with Secondary Subscription Key
			ias->SetSubscriptionKeyID(IAS_Connection::SubscriptionKeyID::Secondary);
			continue;
		}	
		else if (ret != IAS_OK ) {

			printf("IAS return code not ok\n");
			delete req;
			return 0;
		}

		break;
	}
	size_t size;

	*sig_rl = (char *)base64_decode(sigrlstr.c_str(), &size);
	if ( *sig_rl == NULL ) {
		printf("Could not decode SigRL\n");
		delete req;
		return 0;
	}

	*sig_rl_size = (uint32_t)size;
	delete req;
	if (debug)
		printf("IAS OK and SigRL size is %d\n", *sig_rl_size);
	return 1;
}

int get_attestation_report(IAS_Connection *ias,
	const char *b64quote, struct PropertyType secprop, bool *trusted) 
{
	IAS_Request *req = NULL;
	map<string,string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;
	int strict_trust = 0;
	int verbose = 0;
	int debug = 0;
	int version = IAS_API_DEF_VERSION;

	try {
		req= new IAS_Request(ias, (uint16_t) IAS_API_DEF_VERSION);
	}
	catch (...) {
		printf("Exception while creating IAS request object\n");
		if ( req != NULL ) delete req;
		return 0;
	}

	payload.insert(make_pair("isvEnclaveQuote", b64quote));
	
	status= req->report(payload, content, messages);

	std::set<std::string> advisories;
	if ( status == IAS_OK ) {
		JSON reportObj = JSON::Load(content);

		if ( verbose ) {
			printf("%s\n", content.c_str());
			if ( messages.size() ) {
				for (vector<string>::const_iterator i = messages.begin();
					i != messages.end(); ++i ) {

					printf("%s\n", i->c_str());
				}
			}
		}

		if ( verbose ) {
				if ( version >= 3 ) {
					printf("version               = %lu\n",
						reportObj["version"].ToInt());
				}
				printf("id:                   = %s\n",
					reportObj["id"].ToString().c_str());
				printf("timestamp             = %s\n",
					reportObj["timestamp"].ToString().c_str());
				printf("isvEnclaveQuoteStatus = %s\n",
					reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
				printf("isvEnclaveQuoteBody   = %s\n",
					reportObj["isvEnclaveQuoteBody"].ToString().c_str());


				printf("platformInfoBlob  = %s\n",
					reportObj["platformInfoBlob"].ToString().c_str());
				printf("revocationReason  = %s\n",
					reportObj["revocationReason"].ToString().c_str());
				printf("pseManifestStatus = %s\n",
					reportObj["pseManifestStatus"].ToString().c_str());
				printf("pseManifestHash   = %s\n",
					reportObj["pseManifestHash"].ToString().c_str());
				printf("nonce             = %s\n",
					reportObj["nonce"].ToString().c_str());
				printf("epidPseudonym     = %s\n",
					reportObj["epidPseudonym"].ToString().c_str());
				if ( version >= 4 ) {
					int i;

					printf("advisoryURL       = %s\n",
						reportObj["advisoryURL"].ToString().c_str());
					printf("advisoryIDs       = ");
					for(i= 0; i< reportObj["advisoryIDs"].length(); ++i) {
						printf("%s%s", (i)?",":"", reportObj["advisoryIDs"][i].ToString().c_str());
					}
					printf("\n");
				}
		}

		/*
		* If the report returned a version number (API v3 and above), make
		* sure it matches the API version we used to fetch the report.
		*
		* For API v3 and up, this field MUST be in the report.
		*/

		if ( reportObj.hasKey("version") ) {
			unsigned int rversion= (unsigned int) reportObj["version"].ToInt();
			if ( verbose )
				printf("+++ Verifying report version against API version\n");
			if ( version != rversion ) {
				printf("Report version %u does not match API version %u\n",
					rversion , version);
				delete req;
				return 0;
			}
		} else if ( version >= 3 ) {
			printf("attestation report version required for API version >= 3\n");
			delete req;
			return 0;
		}

		/*
		* This sample's attestion policy is based on isvEnclaveQuoteStatus:
		* 
		*   1) if "OK" then return "Trusted"
		*
		*   2) if "CONFIGURATION_NEEDED", "SW_HARDENING_NEEDED", or
		*      "CONFIGURATION_AND_SW_HARDENING_NEEDED", then return
				"NotTrusted_ItsComplicated" when in --strict-trust-mode
				and "Trusted_ItsComplicated" otherwise
		*
		*   3) return "NotTrusted" for all other responses
		*
		* In case #2, this is ultimatly a policy decision. Do you want to
		* trust a client that is running with a configuration that weakens
		* its security posture? Even if you ultimately choose to trust the
		* client, the "Trusted_ItsComplicated" response is intended to 
		* tell the client "I'll trust you (for now), but inform the user
		* that I may not trust them in the future unless they take some 
		* action". A real service would provide some guidance to the
		* end user based on the advisory URLs and advisory IDs.
		*/

		/*
		* Simply check to see if status is OK, else enclave considered 
		* not trusted
		*/

		//if ( verbose ) edividerWithText("ISV Enclave Trust Status");
		for(int i = 0; i< reportObj["advisoryIDs"].length(); ++i) {
			advisories.insert(reportObj["advisoryIDs"][i].ToString());
		}

		std::set<std::string> dissalowed_advisories;
		std::set_difference(advisories.begin(), advisories.end(),
			allowed_advisories.begin(), allowed_advisories.end(),
			std::inserter(dissalowed_advisories, dissalowed_advisories.begin()));

		if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
			*trusted = true;
			printf("Enclave TRUSTED\n");
		} else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED"))) {
			printf("Enclave TRUSTED and COMPLICATED - Reason: %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			*trusted = true;
		} else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE"))) {
			*trusted = false;
			printf("Enclave NOT TRUSTED - group is out of data:\n");
		} else {
			*trusted = false;
			
			if (reportObj["isvEnclaveQuoteStatus"].ToString() == "SW_HARDENING_NEEDED") {
				if (dissalowed_advisories.empty()) {
					*trusted = true;
				} else {
					printf("Enclave NOT TRUSTED - becuase software hardening is needed");
					printf("List of advisories:\n");
					for (auto e: dissalowed_advisories) {
						printf("%s", e.c_str());
					}
				}
			}
		}

		delete req;
		return 1;
	}

	printf("attestation query returned %u: \n", status);

	switch(status) {
		case IAS_QUERY_FAILED:
			printf("Could not query IAS\n");
			break;
		case IAS_BADREQUEST:
			printf("Invalid payload\n");
			break;
		case IAS_UNAUTHORIZED:
			printf("Failed to authenticate or authorize request\n");
			break;
		case IAS_SERVER_ERR:
			printf("An internal error occurred on the IAS server\n");
			break;
		case IAS_UNAVAILABLE:
			printf("Service is currently not able to process the request. Try again later.\n");
			break;
		case IAS_INTERNAL_ERROR:
			printf("An internal error occurred while processing the IAS response\n");
			break;
		case IAS_BAD_CERTIFICATE:
			printf("The signing certificate could not be validated\n");
			break;
		case IAS_BAD_SIGNATURE:
			printf("The report signature could not be validated\n");
			break;
		default:
			if ( status >= 100 && status < 600 ) {
				printf("Unexpected HTTP response code\n");
			} else {
				printf("An unknown error occurred.\n");
			}
	}

	delete req;

	return 0;
}

sgx_measurement_t my_mr_signer;
static int _init= 0;

int verify_enclave_identity(sgx_prod_id_t req_isv_product_id, sgx_isv_svn_t min_isvsvn,
	int allow_debug, sgx_report_body_t *report)
{
	// Does the ISV product ID meet the minimum requirement?
	if ( report->isv_prod_id != req_isv_product_id ) {
		printf("ISV Product Id mismatch: saw %u, expected %u\n",
			report->isv_prod_id, req_isv_product_id);

		return 0;
	}

	// Does the ISV SVN meet the minimum version?
	if ( report->isv_svn < min_isvsvn ) {
		printf("ISV SVN version too low: %u < %u\n", report->isv_svn,
			min_isvsvn);

		return 0;
	}

	return 1;
}