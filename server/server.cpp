#include <iostream>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>

#include "greetings.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::ServerWriter;

using greetings::HelloRequest;
using greetings::HelloReply;
using greetings::Greeter;
using greetings::NoParams;
using greetings::VectorElement;

std::vector<int> globalVector;

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
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
        std::cout << "Inside GetVector" << std::endl;
        for (int i = 0; i < globalVector.size(); ++i) {
            VectorElement element;
            element.set_num(globalVector[i]);
            writer->Write(element);
        }
        return Status::OK;
    }
};


void RunServer() {
    for (int i = 0; i < 100; ++i) {
        globalVector.push_back(i + 1);
    }

    std::string server_address("0.0.0.0:50051");
    GreeterServiceImpl service;

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
