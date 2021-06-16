#include <iostream>
#include <memory>
#include <string>
#include <cstdio>

#include <grpc++/grpc++.h>

#include "data_server.grpc.pb.h"

#include "../common/sgx_declarations.hpp"
#include "crypto_functions.hpp"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using grpc::ServerWriter;

using data_exchange::HelloRequest;
using data_exchange::HelloReply;
using data_exchange::DataServer;
using data_exchange::NoParams;
using data_exchange::VectorElement;
using data_exchange::AttestationMsg0andMsg1;
using data_exchange::AttestationMsg2;
using data_exchange::AttestationMsg3;
using data_exchange::AttestationMsg4;

#include <string>
#include <sstream>


#include "../common/encryption.hpp"
#include "../common/utils.hpp"
#include "iasrequest.hpp"
#include "ias_services.hpp"

std::vector<int> globalVector;

static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

SPIDType SPID;
IAS_Connection *ias = NULL;
unsigned char pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE+1] = "b94ae2aef38c48e98c4b98e06c531bf6";
unsigned char sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE+1] = "83548b6ae777400d8aa6586cadbf34f8";
X509_STORE *cert_store;
EVP_PKEY *g_service_private_key;

// Logic and data behind the server's behavior.
class DataServerServiceImpl final : public DataServer::Service {
    Status SayHello(ServerContext * context, const HelloRequest * request, HelloReply * reply) override {
        std::string prefix("You're welcome ");
        reply->set_message(prefix + request->name() + "!");
        return Status::OK;
    }

    Status SayHelloAgain(ServerContext* context, const HelloRequest* request,
                       HelloReply* reply) override {
        std::string prefix("You're welcome AGAIN ");
        reply->set_message(prefix + request->name() + "!");
        return Status::OK;                  
     }

     Status GetVector(ServerContext* context, const NoParams* empty,
                    ServerWriter<VectorElement>* writer) override {
        std::cout << "Got a call from " << context->peer() << std::endl;
        std::cout << "Inside GetVector" << std::endl;
        std::cout << "Vector size: " << globalVector.size() << std::endl;

        cmac128(kdk_, (unsigned char *)("\x01MK\x00\x80\x00"), 6, mk_);
        for (int i = 0; i < globalVector.size(); ++i) {
            VectorElement element;
            std::stringstream ss;
            ss << globalVector[i];
            std::string str = ss.str();
            std::string encrypted = encrypt_message(str, mk_);
            element.set_num(encrypted);
            writer->Write(element);
        }
        std::cout << std::endl;
        return Status::OK;
    }

    Status StartAttestation(ServerContext* context,
        const AttestationMsg0andMsg1* msg01, AttestationMsg2* msg2) {

        // IAS only supports zero extended EPID
        if (msg01->extended_epid_group_id() != 0) {
            return Status(StatusCode::INVALID_ARGUMENT, "Non-Zero EPID Group Id");
        }

        // Generate Server side public key for the connection
        EVP_PKEY *Gb = key_generate();
        if (!Gb) {
            return Status(StatusCode::INTERNAL, "Couldn't generate server's session key");
        }

        ec256Key Ga;
        memcpy(Ga.gx, msg01->ga_x().c_str(), 16);
        memcpy(Ga.gy, msg01->ga_y().c_str(), 16);

        if(!derive_kdk(Gb, kdk_, Ga)) {
            return Status(StatusCode::INTERNAL, "Couldn't derive KDK");
        }

        /*
        * Derive the SMK from the KDK 
        * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00) 
        */
        cmac128(kdk_, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, smk_);

        /*
        * Build message 2
        *
        * A || CMACsmk(A) || SigRL
        * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
        *
        * where:
        *
        * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga) 
        *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
        * Ga     = Client enclave's session key
        *          (32 bytes)
        * Gb     = Service Provider's session key
        *          (32 bytes)
        * SPID   = The Service Provider ID, issued by Intel to the vendor
        *          (16 bytes)
        * TYPE   = Quote type (0= linkable, 1= linkable)
        *          (2 bytes)
        * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
        *          (2 bytes)
        * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
        *          (signed with the Service Provider's private key)
        *          (64 bytes)
        *
        * CMACsmk= AES-128-CMAC(A)
        *          (16 bytes)
        * 
        * || denotes concatenation
        *
        * Note that all key components (Ga.x, etc.) are in little endian 
        * format, meaning the byte streams need to be reversed.
        *
        * For SigRL, send:
        *
        *  SigRL_size || SigRL_contents
        *
        * where sigRL_size is a 32-bit uint (4 bytes). This matches the
        * structure definition in sgx_ra_msg2_t
        */

        Msg2Type *msg2_as_struct = new Msg2Type();
        memset(msg2_as_struct, 0, sizeof(Msg2Type));

        ec256Key Gb_to_send;
        key_to_sgx_ec256(&Gb_to_send, Gb);
        msg2_as_struct->g_b = Gb_to_send;
        msg2->set_gb_x(Gb_to_send.gx, SGX_ECP256_KEY_SIZE);
        msg2->set_gb_y(Gb_to_send.gy, SGX_ECP256_KEY_SIZE);
       
        msg2_as_struct->spid = SPID;
        msg2->set_spid(convertUIntArray(SPID.id, 16));

        msg2_as_struct->quote_type = 0;
        msg2->set_quote_type(0);

        msg2_as_struct->kdf_id = 1;
        msg2->set_kdf_id(1);

        convertToUIntArray(msg01->gid(), gid_);
        char *sigrl = NULL;
        if (!get_sigrl(ias, gid_, &sigrl, &msg2_as_struct->sig_rl_size));
        {
            return Status(StatusCode::INTERNAL, "Could not retrieve the sigrl");
	    }

        unsigned char digest[32], r[32], s[32], gb_ga[128];
        memcpy(gb_ga, &msg2_as_struct->g_b, 64);
        memcpy(g_b_, &msg2_as_struct->g_b, 64);
        memcpy(&gb_ga[64], &Ga, 64);
        memcpy(g_a_, &Ga, 64);
        ecdsa_sign(gb_ga, 128, g_service_private_key, r, s, digest);

        reverse_bytes(&msg2_as_struct->sign_gb_ga.x, r, 32);
        reverse_bytes(&msg2_as_struct->sign_gb_ga.y, s, 32);

        cmac128(smk_, (unsigned char *) msg2_as_struct, 148, (unsigned char *) &msg2_as_struct->mac);

        {
            std::string gbax;
            convertIntArrayToBytes(msg2_as_struct->sign_gb_ga.x, SGX_NISTP_ECP256_KEY_SIZE, gbax);
            msg2->set_gb_ga_x(gbax);
        }
        {
            std::string gbay;
            convertIntArrayToBytes(msg2_as_struct->sign_gb_ga.y, SGX_NISTP_ECP256_KEY_SIZE, gbay);
            msg2->set_gb_ga_y(gbay);
        }
        msg2->set_mac(convertUIntArray(msg2_as_struct->mac, SGX_MAC_SIZE));
        msg2->set_sig_rl_size(msg2_as_struct->sig_rl_size);

        std::string sigRLBytes(sigrl, sigrl + msg2_as_struct->sig_rl_size);
        msg2->set_sig_rl(sigRLBytes);

        return Status::OK;
    }


    Status CompleteAttestation(ServerContext* context,
        const AttestationMsg3* msg3, AttestationMsg4* msg4) {
        
        // 1. Match Ga from msg1 with this one
        ec256Key Ga;
        convertToUIntArray(msg3->ga_x(), Ga.gx);
        convertToUIntArray(msg3->ga_y(), Ga.gy);

        if (CRYPTO_memcmp(&Ga, &g_a_, sizeof(ec256Key))) {
		    return Status(StatusCode::FAILED_PRECONDITION, "msg1.g_a and mgs3.g_a keys don't match");
        }

        size_t quote_size = msg3->quote_size();
        MacType vrfymac;

        cmac128(smk_, (unsigned char *)&Ga, sizeof(Msg3Type) - sizeof(MacType) + quote_size, (unsigned char *)vrfymac);

        if (CRYPTO_memcmp(msg3->mac().c_str(), vrfymac, sizeof(MacType)) ) {
            return Status(StatusCode::FAILED_PRECONDITION, "Failed to verify msg3 MAC");
	    }

        char *b64quote = base64_encode(msg3->quote().c_str(), quote_size);
        if ( b64quote == NULL ) {
            return Status(StatusCode::FAILED_PRECONDITION, "Could not base64 encode the quote");
	    }

        QuoteType *q = (QuoteType*)msg3->quote().c_str();
        if ( memcmp(gid_, &q->epid_group_id, sizeof(GroupId)) ) {
            return Status(StatusCode::FAILED_PRECONDITION, "EPID GID mismatch. Attestation failed");
	    }

        bool trusted;
        PropertyType sec_prop;
        convertToUIntArray(msg3->ps_sec_prop(), sec_prop.sgx_ps_sec_prop_desc);
        
        if ( get_attestation_report(ias, b64quote, sec_prop, &trusted) ) {
            		unsigned char vfy_rdata[64];
            unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

            sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;

            memset(vfy_rdata, 0, 64);

            /*
                * Verify that the first 64 bytes of the report data (inside
                * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
                *
                * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
                *
                * where || denotes concatenation.
                */

            /* Derive VK */

            cmac128(kdk_, (unsigned char *)("\x01VK\x00\x80\x00"),
                    6, vk_);

            /* Build our plaintext */

            memcpy(msg_rdata, g_a_, 64);
            memcpy(&msg_rdata[64], g_b_, 64);
            memcpy(&msg_rdata[128], vk_, 16);

            /* SHA-256 hash */

            sha256_digest(msg_rdata, 144, vfy_rdata);

            if ( CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data, 64) ) {

                printf("Report verification failed.\n");
            }

            /*
                * If the enclave is trusted, derive the MK and SK. Also get
                * SHA256 hashes of these so we can verify there's a shared
                * secret between us and the client.
                */

            if ( trusted ) {
                unsigned char hashmk[32], hashsk[32];

                cmac128(kdk_, (unsigned char *)("\x01MK\x00\x80\x00"),
                    6, mk_);
                cmac128(kdk_, (unsigned char *)("\x01SK\x00\x80\x00"),
                    6, sk_);

                sha256_digest(mk_, 16, hashmk);
                sha256_digest(sk_, 16, hashsk);
            }
        }

	}

	unsigned char g_a_[64];
	unsigned char g_b_[64];
	unsigned char kdk_[16];
	unsigned char smk_[16];
	unsigned char sk_[16];
	unsigned char mk_[16];
	unsigned char vk_[16];
    GroupId gid_;
};


void RunServer() {
    crypto_init();
    g_service_private_key = key_private_from_bytes(def_service_private_key);
    try {
		ias = new IAS_Connection(IAS_SERVER_DEVELOPMENT, 0,
			(char *)(pri_subscription_key),
			(char *)(sec_subscription_key)
		);
        ias->proxy_mode(IAS_PROXY_NONE);
        
        {
            X509 *signing_ca;
            if (!cert_load_file(&signing_ca, "Intel_SGX_Attestation_RootCA.pem")) {
                crypto_perror("cert_load_file");
                printf("Could not load IAS Signing Cert CA\n");
            }

            cert_store = cert_init_ca(signing_ca);
            ias->cert_store(cert_store);
        }
	}
	catch (...) {
		printf("exception while creating IAS request object\n");
	}

    

    encrypt_example();

    const char spid[33] = "EE2913B7001E0EB387C64455527F625F";
    from_hexstring(SPID.id, (void*)spid, 16);

    std::string server_address("0.0.0.0:50051");
    DataServerServiceImpl service;

    ServerBuilder builder;
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // Register "service" as the instance through which we'll communicate with clients. 
    // In this case it corresponds to an *synchronous* service.
    builder.RegisterService(&service);
    // Finally assemble the server.
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    // Wait for the server to shutdown. 
    // Note that some other thread must be responsible for shutting down the server for this call to ever return.
    server->Wait();
}

int main(int argc, char ** argv) {
    RunServer();
    return 0;
}

