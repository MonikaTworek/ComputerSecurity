#include "bserver.h"

bserver::bserver() {
    num = BN_new();
    ctx = BN_CTX_new();
    ctx_mont = NULL ;
}

void bserver::setup(char* path) {
    // Generate rsa key
    ret = BN_set_word(num, RSA_F4);         //num == e
    if(ret != 1) {
        std::cout << "Error. Ending" << std::endl;
    }

    generate_password();

    // Generate key pairs
    generate_key_pair(2048, path);
    generate_key_pair(4096, path);
//    generate_key_pair(8192, path);
//    generate_key_pair(16384, path);
}

void bserver::generate_password() {
    auto *p = generate_random_bytes(LENGTH);
    auto *password = code_base64(p, LENGTH);
    std::cout << "Generated pass: " << password << std::endl;
    auto *s = generate_random_bytes(LENGTH);
    auto *salt = code_base64(s, LENGTH);

    unsigned char out[HASH_LEN];
    memset(out, 0, sizeof out);

    if(PKCS5_PBKDF2_HMAC(password, LENGTH, reinterpret_cast<const unsigned char *>(salt), LENGTH, ITERS, EVP_sha256(), HASH_LEN, out) != 1) {
        std::cout << "Failure" << std::endl;
    }

    auto *key = code_base64(out, HASH_LEN);

    std::ofstream out_pass("server_pass");
    std::ofstream out_salt("server_salt");
    out_pass << key;
    out_salt << salt;
}

unsigned char* bserver::generate_random_bytes(int size) {
    auto *buff = (unsigned char*)(malloc(size + 1));

    if (!RAND_bytes(buff, size)) {
        return NULL;
    }

    return buff;
}

char* bserver::code_base64(unsigned char *buff, int size) {
    char *bytes = NULL;
    BIO *b64, *out;
    BUF_MEM *bptr;

    // Create a base64 filter/sink
    if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
        return NULL;
    }

    // Create a memory source
    if ((out = BIO_new(BIO_s_mem())) == NULL) {
        return NULL;
    }

    // Chain them
    out = BIO_push(b64, out);
    BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);

    // Write the bytes
    BIO_write(out, buff, size);
    BIO_flush(out);

    // Now remove the base64 filter
    out = BIO_pop(b64);

    // Write the null terminating character
    BIO_write(out, "\0", 1);
    BIO_get_mem_ptr(out, &bptr);

    // Allocate memory for the output and copy it to the new location
    bytes = (char*)malloc(bptr->length);
    strncpy(bytes, bptr->data, bptr->length);

    // Cleanup
    BIO_set_close(out, BIO_CLOSE);
    BIO_free_all(out);
//    free(buff);

    return bytes;
}

void bserver::generate_key_pair(int key_length, char* path_to_save) {
    // Measure elapsed time
    auto start = std::chrono::high_resolution_clock::now();

    r = RSA_new();
    ret = RSA_generate_key_ex(r, key_length, num, NULL);
    if(ret != 1) {
        std::cout << "Error. Ending" << std::endl;
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Generate " << key_length << " keys time: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count() << "ms" << std::endl;

    const BIGNUM *N = BN_new();
    const BIGNUM *d = BN_new();
    const BIGNUM *e = BN_new();
    RSA_get0_key(r, &N, &e, &d);

    char p[30];
    FILE *file;
    std::string s = std::to_string(key_length);
    char const *length = s.c_str();

    // Save public key
    memset(p, 0, sizeof p);
    strcat(p, path_to_save);
    strcat(p, "public");
    strcat(p, length);

    file = fopen(p , "w+");
    BN_print_fp(file, N);
    fprintf(file, "\n");
    BN_print_fp(file, e);
    fclose(file);

    // Save private key
    memset(p, 0, sizeof p);
    strcat(p, path_to_save);
    strcat(p, "private");
    strcat(p, length);

    file = fopen(p , "w+");
    BN_print_fp(file, N);
    fprintf(file, "\n");
    BN_print_fp(file, d);
    fclose(file);

    std::cout << "Key " << key_length << " generated" << std::endl << std::endl;
}

void bserver::communicate_with_client(char *password, int port, char *key_path) {
    // If pass is not correct -> end
    if(!is_server_password_valid(password)) {
        std::cout << "Given password is not correct. Aborting..." << std::endl;
        return;
    }
    std::cout << "Given password is correct" << std::endl << std::endl;

    // Load proper private key (N, d)
    read_key_from_file(key_path);

    // Start server
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the given port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("server_listen");
        exit(EXIT_FAILURE);
    }

    while(true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *) &address, (socklen_t *) &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Get message from client
        read(new_socket, buffer, BUFFER_SIZE);
        BIGNUM *m = BN_new();
        BN_hex2bn(&m, buffer);
        std::cout << "Message received from client" << std::endl;

        // If x is not in Zn group -> abort
        if (!is_msg_in_group(m)) {
            std::cout << "Message x is not in Zn. Aborting..." << std::endl << std::endl;
            return;
        }
        std::cout << "Message x is in Zn." << std::endl;

        // Send signed message to client
        std::cout << "Signing..." << std::endl;
        char *signed_msg = sign_msg(m);
        send(new_socket, signed_msg, strlen(signed_msg), 0);
        std::cout << "Signed msg sent to client" << std::endl << std::endl;
        BN_free(m);
    }
}

bool bserver::is_server_password_valid(char *user_pass) {
    std::string pass;
    std::ifstream myfile("server_pass");
    if (myfile.is_open()) {
        while (std::getline(myfile, pass));
        myfile.close();
    }

    std::string salt;
    std::ifstream myfile2("server_salt");
    if (myfile2.is_open()) {
        while(std::getline(myfile2, salt));
        myfile2.close();
    }

    unsigned char out[HASH_LEN];
    memset(out, 0, sizeof out);

    // Hash user's pass
    if(PKCS5_PBKDF2_HMAC(user_pass, LENGTH, reinterpret_cast<const unsigned char *>(salt.c_str()), LENGTH, ITERS, EVP_sha256(), HASH_LEN, out) != 1) {
        std::cout << "Failure" << std::endl;
    }

    auto *key = code_base64(out, HASH_LEN);

    if(key == pass) {
        return true;
    }

    return false;
}

void bserver::read_key_from_file(char *path) {
    std::cout << "Loading key from: " << path << std::endl;
    std::string item_name;
    std::ifstream nameFileout;
    nameFileout.open(path);
    std::string line;

    //TODO free 'temp' ?
    auto *temp = new std::string[2];
    int i = 0;
    while(std::getline(nameFileout, line)) {
        temp[i] = line;
        i++;
    }

    const char *c = temp[0].c_str();
    BN_hex2bn(&N, c);
    c = temp[1].c_str();
    BN_hex2bn(&d, c);
}

bool bserver::is_msg_in_group(BIGNUM *num) {
    // If num is in group -> gcd(num,N) == 1
    BIGNUM *gcd = BN_new();
    BIGNUM *one = BN_new();
    BN_gcd(gcd, num, N, ctx);
    int ret = BN_cmp(one, gcd);
    BN_free(gcd);
    BN_free(one);

    return ret != 0;
}

char* bserver::sign_msg(BIGNUM *msg_to_sign) {
    // s'= (m')^d (mod N)

    // Measure time

    //TODO
    BIGNUM *d_const = BN_new();
    BN_with_flags(d_const, d, BN_FLG_CONSTTIME);
    BIGNUM *result = BN_new();

    auto start = std::chrono::high_resolution_clock::now();
    BN_mod_exp(result, msg_to_sign, d, N, ctx);
//    BN_mod_exp_mont_consttime(result, msg_to_sign, d_const, N, ctx, ctx_mont);
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Signing time: ";
    double diff = std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count();
    std::cout << diff << "ms" << std::endl;

    BN_free(d_const);

    char *ret = BN_bn2hex(result);
    BN_free(result);
    return ret;
}

bserver::~bserver() {
    RSA_free(r);
    BN_free(num);
    BN_free(N);
    BN_free(d);
    BN_CTX_free(ctx);
}

int main(int argc, char*argv[]) {
    if(argc < 3) {
        std::cout << "Missing arguments. Aborting..." << std::endl;
        return -1;
    }

    bserver *server = new bserver();

    if(strcmp(argv[1], "setup") == 0) {
        std::cout << "Setup mode started" << std::endl;
        server->setup(argv[2]);
        return 0;
    }

    if(argc < 5) {
        std::cout << "Missing arguments" << std::endl;
        return -1;
    }

    if(strcmp(argv[1], "sign") == 0) {
        std::cout << "Sign mode started\n" << std::endl;
        server->communicate_with_client(argv[2], atoi(argv[3]), argv[4]);
    }
    else {
        std::cout << "Wrong mode selected. Choose 'setup' or 'sign'" << std::endl;
    }

    return 0;
}
