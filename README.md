# sgx-ra-sample

# The rationale

This is a prototype of client-server infrastructure where the server (or service provider) stores sensitive data and client performs computations over it.

Since the machine that processes secure data can be compromised or emulated, the data it operates can be stolen. In order to prevent it, the computations
can be placed in a secure environment such as Intel SGX's enclaves. But still, the problem in this case is how to provide this enclave with the sensitive information.
This is solved by providing the data via a secure channel between a server that stores sensitive data and the enclave itself. In this case the server needs
to decide whether or not to trust that enclave, i.e. it's run on a geninue Intel SGX-enabled hardware, is not tampered with and is not emulated.
This prototype presents a small but complete setup of this infrastructue.
The server attests enclave's identity via the the process of remote attestation in which the enclave proves its identity and the server uses Intel Attestation Service to verify it. Simultaneously a secure channel with symmetric ke encrption is established

# Build

## Dependencies

- cmake 3.13
- Google RPC
- OpenSSL Lib
- LibXML

For the server part:
- LibCurl

For the client part:
- Intel SGX SDK & PSW 3.13

## Prerequisites

In order to use Intel Attestation Services, head to https://api.portal.trustedservices.intel.com/EPID-attestation and obtain credentials for unlinkable
development access, that includes
- SPID (Service Provider ID)
- Subscription Primary Key
- Subscription Secondary Key

and download the site certificalte from https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem 


## How to build

You can build both client and server and launch them on the same platform or you can build only one of them
Use cmake's options BUILD_CLIENT and BUILD_SERVER for it. By default both are built
No additional arguments need to be specified
Example:

```
cmake -B build
cmake --build build
```

To build only the server part:

```
cmake -B build -DBUILD_CLIENT=OFF
cmake --build build
```

# How to Launch
The executables are places in build/client and build/server folder respectively

Launch the server:
```
cd build/server
./server
```

In the separate console launch client:
```
cd build/client
./client
```

On launch the client makes attestation requests, the server does the attestation and upon successful verification sends the client
the list of available datasets.
The client then can select which dataset to process and sends the server the desired dataset name
then the server sends back the sensitive data via symmetrically encrypted channel and the client makes the desired computations in the enclave
The prototpe uses simple vectors as data and the computation is a simple sum of all of its element.
The data is stored in .dat files on the server files and is actually an xml file
The client prints the result of the computations to the console, so a user can chack if it's expected


# Settings explained
Both server and client have settings.xml file that need to be placed to the current directory

## Server settings
 - ip address associated with the server
 - port it listens to
 - key server's private key used to only communicate with the clients that have the right public key
 - spid Service Provider ID used in Intel Attestation Service verification
 - primary_subscription_key IAS Subscription Primary Key
 - secondary_subscription_key IAS Subscription Secondary Key
 - ias_key_file path to the IAS website certificated downloaded

## Client settings
- ip address where client is run
- port it occupies
- public_key 256bit server public key