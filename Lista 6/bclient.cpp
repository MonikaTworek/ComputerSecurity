#include "bclient.h"

bclient::bclient(int port, char *path, char *message) {
    N = BN_new();
    e = BN_new();
    r = BN_new();
    ctx = BN_CTX_new();

    // Load public key (N, e)
    load_publickey_from_file(path);

    // Prepare new message
    BIGNUM *x = calculate_msg(message);

    //Connect with server socket to exchange msgs
    communicate_with_server(port, BN_bn2hex(x));
    BN_free(x);
}

void bclient::load_publickey_from_file(char *path) {
    std::cout << "Loading key from: " << path << std::endl << std::endl;
    std::string item_name;
    std::ifstream nameFileout;
    nameFileout.open(path);
    std::string line;

    auto *temp = new std::string[2];

    int i = 0;
    while(std::getline(nameFileout, line)) {
        temp[i] = line;
        i++;
    }

    const char *c = temp[0].c_str();
    BN_hex2bn(&N, c);
    c = temp[1].c_str();
    BN_hex2bn(&e, c);

    std::cout << "N: " << BN_bn2dec(N) << std::endl << std::endl;
    std::cout << "e: " << BN_bn2dec(e) << std::endl << std::endl;
}

BIGNUM* bclient::calculate_msg(char *msg) {
    // m' = hash(m) * r^e (mod N)

    std::string hashed_msg = sha256(msg);

    const char *hashed_msg_char = hashed_msg.c_str();
    BIGNUM *m = BN_new();
    BN_hex2bn(&m, hashed_msg_char);
    hashed = BN_bn2dec(m);

    BIGNUM *one = BN_new();
    BIGNUM *gcd = BN_new();
    BN_one(one);

    do {
        BN_rand_range(r, N);
        BN_gcd(gcd,r, N, ctx);
    }
    while(BN_cmp(gcd, one) != 0);

    BIGNUM *x = BN_new();
    BN_mod_exp(x, r, e, N, ctx);
    BN_mod_mul(x, m, x, N, ctx);

    BN_free(one);
    BN_free(gcd);
    BN_free(m);
    return x;
}

std::string bclient::sha256(const std::string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void bclient::communicate_with_server(int port, char *msg) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char signed_msg[BUFFER_SIZE] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return;
    }

    // Send msg to server
    send(sock, msg, strlen(msg), 0);
    std::cout << "Msg sent to server: " << msg << std::endl << std::endl;

    // Get signed response
    read(sock, signed_msg, BUFFER_SIZE);
    std::cout << "Signed msg received from the server: " << signed_msg << std::endl << std::endl;

    remove_signature(signed_msg);
}

void bclient::remove_signature(char *msg_to_unsign) {
    // s = s' * r^-1 (mod N)

    BIGNUM *from = BN_new();
    BIGNUM *inverse = BN_new();
    BIGNUM *s = BN_new();
    BN_hex2bn(&from, msg_to_unsign);

    BN_mod_inverse(inverse, r, N, ctx);
    BN_mod_mul(s, inverse, from, N, ctx);

    // Verify msg
    if(bverfy(s))
        std::cout << "VERIFY: true" << std::endl << std::endl;
    else
        std::cout << "VERIFY: false" << std::endl << std::endl;

    BN_free(from);
    BN_free(inverse);
    BN_free(s);
}

bool bclient::bverfy(BIGNUM *msg) {
    // If [s^e (mod N) == hash(m)]

    // Measure time
    auto start = std::chrono::high_resolution_clock::now();

    BIGNUM *h = BN_new();
    BN_mod_exp(h, msg, e, N, ctx);

    std::cout << "computed: " << BN_bn2dec(h) << std::endl;
    std::cout << "original: " << hashed << std::endl;
    int ret = strcmp(hashed, BN_bn2dec(h));

    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Verifying time: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count() << "ms" << std::endl;

    BN_free(h);
    return ret == 0;
}

bclient::~bclient() {
    BN_free(N);
    BN_free(e);
    BN_free(r);
    BN_CTX_free(ctx);
}

int main(int argc, char*argv[]) {
    if(argc < 4) {
        std::cout << "Missing arguments" << std::endl;
        return -1;
    }

    bclient *client = new bclient(atoi(argv[1]), argv[2], argv[3]);
    return 0;
}
