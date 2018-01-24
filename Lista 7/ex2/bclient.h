#ifndef SIGNATURER_BCLIENT_H
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 4096
#define BN_FLG_CONSTTIME   0x04
#define BN_FLG_SECURE      0x08
#define SIGNATURER_BCLIENT_H


class bclient {
private:
    BIGNUM *N, *e, *r;
    BN_CTX *ctx;
    BN_MONT_CTX *ctx_mont;
    const char* hashed;

    void load_publickey_from_file(char *path);
    BIGNUM *calculate_msg(char *msg);
    std::string sha256(std::string str);
    void communicate_with_server(int port, char *msg);
    void remove_signature(char *msg_to_unsign);
    bool bverfy(BIGNUM *msg);
    ~bclient();
public:
    bclient(int port, char* public_key_path, char* message_to_sign);
};

#endif //SIGNATURER_BCLIENT_H
