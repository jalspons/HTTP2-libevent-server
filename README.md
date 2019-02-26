# HTTP2 testing with nghttp2

## Introduction

#### This work was conducted for the Internet Protocols course. The assignment consisted of two parts:
1. Build a HTTP2-server
2. Choose two features introduced with HTTP2 and measure how they improve the HTTP protocol functionalities (HTTP1 vs. HTTP2)


The implementation consists of server and client implementations for testing multiplexing and server push features. 

The repository also includes some implementations of HTTP1 servers. 

## Dependencies
* nghttp2
* libevent
* openssl

## Usage

TLS is enabled on the connection, so prepare also certs and fix the testscript linking.

```
cd test
./testsuite.sh
```
