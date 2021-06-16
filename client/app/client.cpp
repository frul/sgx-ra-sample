#include <iostream>
#include <memory>
#include <string>
#include <sstream>

#include <grpc++/grpc++.h>

#include "data_server.grpc.pb.h"

#include "../../common/encryption.hpp"
#include "../../common/utils.hpp"

#include "enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils.h"
#include <sgx_ukey_exchange.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::ClientReader;

using data_exchange::HelloRequest;
using data_exchange::HelloReply;
using data_exchange::DataServer;
using data_exchange::NoParams;
using data_exchange::VectorElement;

sgx_enclave_id_t global_eid = 0;

int ReduceVector(const std::vector<std::string>& vec) {
    int result = 0;
    unsigned char *key = getPublicKey();
    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char decryptedtext[128];
    for (auto e: vec) {     
        result += decrypt_message((unsigned char*)e.c_str());
    }
    return result;
}

int initialize_enclave(sgx_enclave_id_t* eid, const std::string& launch_token_path, const std::string& enclave_name) {
    const char* token_path = launch_token_path.c_str();
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    FILE* fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    if (ret != SGX_SUCCESS) {
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}


class DataServerClient {
public:
    // Constructor
    DataServerClient(std::shared_ptr<Channel> channel): stub_(DataServer::NewStub(channel)) {}
    // Assembles the client's payload, sends it and presents the response back from the server.
    std::string SayHello(const std::string & user) {
        // Data we are sending to the server.
        HelloRequest request;
        request.set_name(user);

        // Container for the data we expect from the server.
        HelloReply reply;

        // Context for the client. 
        // It could be used to convey extra information to the server and/or tweak certain RPC behaviors.
        ClientContext context;

        // The actual RPC.
        Status status = stub_->SayHello(&context, request, &reply);

        // Act upon its status.
        if (status.ok()) {
            return reply.message();
        } 
        else {
            std::cout << status.error_code() << ": " << status.error_message() << std::endl;
            return "gRPC failed";
        }
    }

    std::string SayHelloAgain(const std::string& user) {
        // Follows the same pattern as SayHello.
        HelloRequest request;
        request.set_name(user);
        HelloReply reply;
        ClientContext context;

        // Here we can use the stub's newly available method we just added.
        Status status = stub_->SayHelloAgain(&context, request, &reply);
        if (status.ok()) {
            return reply.message();
        } else {
        std::cout << status.error_code() << ": " << status.error_message()
                    << std::endl;
        }
        return "RPC failed";
    }

    void PrintScore() {
        ClientContext context;
        NoParams no_params;
        std::unique_ptr<ClientReader<VectorElement> > reader(
            stub_->GetVector(&context, no_params));
        std::vector<std::string> received_vector;
        VectorElement element;
        while (reader->Read(&element)) {
            received_vector.push_back(element.num());
        }
        Status status = reader->Finish();
        if (status.ok()) {
            std::cout << "GetVecor succeeded." << std::endl;
        } else {
            std::cout << "GetVector failed." << std::endl;
        }

        char** array_to_pass = new char*[received_vector.size()];
        for (int i = 0; i < received_vector.size(); ++i) {
            std::string e = received_vector[i];
            array_to_pass[i] = new char[e.length() + 1];
            strcpy(array_to_pass[i], e.c_str()); 
        }

        int score;
        ecall_compute_score(global_eid, &score, array_to_pass, received_vector.size());
        std::cout << "Reduced vector result: " << score << std::endl;
    }

    int init() {
        if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
            std::cout << "Fail to initialize enclave." << std::endl;
            return -1;
        }
        return 0;
    }

    
    bool attest() {
        sgx_status_t status, sgxrv;
        sgx_ra_context_t ra_ctx = 0x0;
        status = ecall_initialize_ra(global_eid, &sgxrv, &ra_ctx);
        if (status != SGX_SUCCESS) {
            std::stringstream ss;
            ss << "enclave_ra_init: " << std::hex << status;
            throw std::runtime_error(ss.str());
        }

        uint32_t msg0_extended_epid_group_id = 0;
        status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
        if ( status != SGX_SUCCESS ) {
            std::stringstream ss;
            ss << "sgx_get_extended_epid_group_id: " << std::hex << status;
            throw std::runtime_error(ss.str());
        }

        sgx_ra_msg1_t msg1;
        status = sgx_ra_get_msg1(ra_ctx, global_eid, sgx_ra_get_ga, &msg1);
        if ( status != SGX_SUCCESS ) {
            std::stringstream ss;
            ss << "sgx_ra_get_msg1: " << std::hex << status;
            throw std::runtime_error(ss.str());
        }

        data_exchange::AttestationMsg2 server_msg2;
        {
            data_exchange::AttestationMsg0andMsg1 server_msg01;
            server_msg01.set_extended_epid_group_id(msg0_extended_epid_group_id);
            server_msg01.set_ga_x((char*)msg1.g_a.gx);
            server_msg01.set_ga_y((char*)msg1.g_a.gy);
            server_msg01.set_gid((char*)msg1.gid);
            ClientContext context;
            Status status = stub_->StartAttestation(&context, server_msg01, &server_msg2);
        }

        sgx_ra_msg2_t *msg2 = new sgx_ra_msg2_t();
        strcpy((char*)msg2->g_b.gx, server_msg2.gb_x().c_str());
        strcpy((char*)msg2->g_b.gy, server_msg2.gb_y().c_str());
        strcpy((char*)msg2->spid.id, server_msg2.spid().c_str());
        msg2->quote_type = server_msg2.quote_type();
        msg2->kdf_id = server_msg2.kdf_id();
        /*strcpy((char*)msg2->g_b.gx, server_msg2.gb_x().c_str());
        strcpy((char*)msg2->g_b.gx, server_msg2.gb_x().c_str());*/
        strcpy((char*)msg2->mac, server_msg2.mac().c_str());
        msg2->sig_rl_size = server_msg2.sig_rl_size();
        strncpy((char*)msg2->sig_rl, server_msg2.sig_rl().c_str(), msg2->sig_rl_size);

	    sgx_ra_msg3_t *msg3 = NULL;
        uint32_t msg3_sz;
        status = sgx_ra_proc_msg2(ra_ctx, global_eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, 
		    sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size, &msg3, &msg3_sz);

        if ( status != SGX_SUCCESS ) {
            std::stringstream ss;
            ss << "sgx_ra_proc_msg2: " << std::hex << status;
            throw std::runtime_error(ss.str());
        }
        
        data_exchange::AttestationMsg4 server_msg4;
        {
            data_exchange::AttestationMsg3 server_msg3;

            {
                std::string mac_as_string;
                convertCharArrayToBytes(msg3->mac, SGX_MAC_SIZE, mac_as_string);
                server_msg3.set_mac(mac_as_string);
            }

            {
                std::string ga_x_as_string;
                convertCharArrayToBytes(msg3->g_a.gx, SGX_ECP256_KEY_SIZE, ga_x_as_string);
                server_msg3.set_ga_x(ga_x_as_string);
            }

            {
                std::string ga_y_as_string;
                convertCharArrayToBytes(msg3->g_a.gy, SGX_ECP256_KEY_SIZE, ga_y_as_string);
                server_msg3.set_ga_y(ga_y_as_string);
            }

            {
                std::string prop_as_string;
                convertCharArrayToBytes(msg3->ps_sec_prop.sgx_ps_sec_prop_desc, 256, prop_as_string);
                server_msg3.set_ps_sec_prop(prop_as_string);
            }

            {
                uint32_t quote_size = msg3_sz - sizeof(sgx_ra_msg3_t);

                /*
                typedef struct _ra_msg3_t
                {
                    sgx_mac_t                mac;         // mac_smk(g_a||ps_sec_prop||quote)
                    sgx_ec256_public_t       g_a;         // the Endian-ness of Ga is Little-Endian
                    sgx_ps_sec_prop_desc_t   ps_sec_prop; // reserved Must be 0 
                    uint8_t                  quote[];
                } sgx_ra_msg3_t;
                */

                server_msg3.set_quote_size(quote_size);
                std::string quote_as_string;
                convertCharArrayToBytes(msg3->quote, quote_size, quote_as_string);
                server_msg3.set_quote(quote_as_string);
            }

            
            ClientContext context;
            Status status = stub_->CompleteAttestation(&context, server_msg3, &server_msg4);
            return server_msg4.ok();
        }     

        return false;
    }


    void getList() {}
    void getData() {}

private:
    std::unique_ptr<DataServer::Stub> stub_;
};

void InterativeGRPC() {

    // Instantiate the client. It requires a channel, out of which the actual RPCs are created. 
    // This channel models a connection to an endpoint (in this case, localhost at port 50051). 
    // We indicate that the channel isn't authenticated (use of InsecureChannelCredentials()).
    DataServerClient dataServerClient(grpc::CreateChannel("localhost:50051", grpc::InsecureChannelCredentials()));
        /*std::string user;
        std::cout << "Please enter your user name:" << std::endl;
        // std::cin >> user;
        std::getline(std::cin, user);
        std::string reply = greeter.SayHello(user);
        if (reply == "gRPC failed") {
            std::cout << "gRPC failed" << std::endl;
        }
        std::cout << "gRPC returned: " << std::endl;
        std::cout << reply << std::endl;

        std::cout << "we sent the greetings again" << std::endl;
        reply = greeter.SayHelloAgain(user);
        if (reply == "gRPC failed") {
            std::cout << "gRPC failed" << std::endl;
        }
        std::cout << "gRPC returned: " << std::endl;
        std::cout << reply << std::endl;*/

    if(!dataServerClient.init()) {
        std::cout << "Failed to initialize the enclave" << std::endl;
    }

    bool attested = false;
    try {
        attested = dataServerClient.attest();
    }
    catch (const std::exception& e) {
        std::cout << "attestation failed with: " << e.what();
    }

    if (!attested) {
        std::cout << "Enclave is not trusted. Exiting" << std::endl;
    }

    try {
        dataServerClient.PrintScore();
    }
    catch (const std::exception& e) {
        std::cout << "PrintScore failed with: " << e.what();
    }

}


int main() {

    InterativeGRPC();

    return 0;
}



