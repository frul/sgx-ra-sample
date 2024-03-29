# Minimum CMake required
cmake_minimum_required(VERSION 3.13)

project(gRPC_CPP_Greetings VERSION 0.0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set (proto_name data_server)

# Get proto files
get_filename_component(proto "../protos/${proto_name}.proto" ABSOLUTE)
get_filename_component(proto_dir "${proto}" DIRECTORY)

# Generate source files
set(proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.pb.cc")
set(proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.pb.h")
set(grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.grpc.pb.cc")
set(grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/${proto_name}.grpc.pb.h")
add_custom_command(
    OUTPUT "${proto_srcs}" "${proto_hdrs}" "${grpc_srcs}" "${grpc_hdrs}"
    COMMAND ${_PROTOBUF_PROTOC}
    ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
    --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
    -I "${proto_dir}"
    --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
    "${proto}"
    DEPENDS "${proto}"
)


find_package(CURL)

set(targets "server")

# Include generated *.pb.h files
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CURL_INCLUDE_DIR})

foreach(target ${targets})

    add_executable(${target} "${target}.cpp" ${proto_srcs} ${grpc_srcs} settings.cpp crypto_functions.cpp base64.cpp agent_wget.cpp agent_curl.cpp iasrequest.cpp ../common/utils.cpp )
    target_link_libraries(${target} PRIVATE ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF} ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} -lstdc++fs)
    message("PRIVATE ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF} ${LIBXML2_LIBRARIES}")
    # Cannot do this because these directories are not available during CMake "compile time"
    # target_include_directories(${proto_hdrs} ${grpc_hdrs})
endforeach()

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/settings.xml DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/alice.dat DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/ivan.dat DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/Intel_SGX_Attestation_RootCA.pem DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

