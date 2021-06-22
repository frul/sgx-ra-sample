set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

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



set(EDL_SEARCH_PATHS enclave)

set(E_SRCS enclave/enclave.cpp)
set(LDS enclave/enclave.lds)
add_enclave_library(enclave SRCS ${E_SRCS} EDL enclave/enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS})
enclave_sign(enclave KEY enclave/Enclave_private.pem CONFIG enclave/enclave.config.xml)

set(targets "client")
set(SRCS app/client.cpp ../common/utils.cpp app/settings.cpp)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_untrusted_executable(client SRCS ${SRCS} ${proto_srcs} ${grpc_srcs} EDL enclave/enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

add_dependencies(client enclave-sign)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/app/settings.xml DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
