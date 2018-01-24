#include "bserver.h"

bserver::bserver() {
    num = BN_new();
    ctx = BN_CTX_new();
}

void bserver::setup(char* path) {
    generate_password();

    // Generate key pairs
//    generate_safe_keys(50, path);
    generate_safe_keys(100, path);
//    generate_safe_keys(4096, path);
//    generate_safe_keys(8192, path);
//    generate_safe_keys(16384, path);

    // Generate worse key pairs
//    generate_weak_keys(50, path);
    generate_weak_keys(100, path);
//    generate_weak_keys(4096, path);
//    generate_weak_keys(8192, path);
//    generate_weak_keys(16384, path);
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

void bserver::generate_safe_keys(int key_length, char *path_to_save) {
    // Measure elapsed time
    auto start = std::chrono::high_resolution_clock::now();

//    Obliczamy wartość n = pq
//    Obliczamy wartość funkcji Eulera dla n: φ ( n ) = ( p − 1 ) ( q − 1 ) {\displaystyle \varphi (n)=(p-1)(q-1)} \varphi (n)=(p-1)(q-1)
//    Wybieramy liczbę e (1 < e < φ(n)) względnie pierwszą z φ(n)
//    Znajdujemy liczbę d, gdzie jej różnica z odwrotnością liczby e jest podzielna przez φ(n) :
//
//    d ≡ e−1 (mod φ(n))
    //TODO
    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();
    BIGNUM *d_safe = BN_new();
    BIGNUM *e_safe = BN_new();
    BIGNUM *n_safe = BN_new();
    BIGNUM *euler = BN_new();
    BN_generate_prime_ex(prime1, key_length/2, 1, NULL, NULL, NULL);
    BN_generate_prime_ex(prime2, key_length/2, 1, NULL, NULL, NULL);

    BN_mul(n_safe, prime1, prime2, ctx);

    BIGNUM *one = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();

    BN_set_word(one, 1);
    BN_sub(temp1, prime1, one);
    BN_sub(temp2, prime2, one);

    BN_mul(euler, temp1, temp2, ctx);

    BIGNUM *gcd = BN_new();
    BN_one(one);

    do {
        BN_rand_range(e_safe, euler);
        BN_gcd(gcd, e_safe, euler, ctx);
    }
    while(BN_cmp(gcd, one) != 0);

    BN_mod_inverse(d_safe, e_safe, euler, ctx);

    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Generate " << key_length << " keys time: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count() << "ms" << std::endl;

    std::cout << "Prime1: " << BN_bn2dec(prime1) << " is safe: " << check_if_strong_prime(prime1) << std::endl;
    std::cout << "Prime2: " << BN_bn2dec(prime2) << " is safe: " << check_if_strong_prime(prime2) << std::endl;

    BN_free(prime1);
    BN_free(prime2);
    BN_free(euler);
    BN_free(one);
    BN_free(temp1);
    BN_free(temp2);
    BN_free(gcd);


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
    BN_print_fp(file, n_safe);
    fprintf(file, "\n");
    BN_print_fp(file, e_safe);
    fclose(file);

    // Save private key
    memset(p, 0, sizeof p);
    strcat(p, path_to_save);
    strcat(p, "private");
    strcat(p, length);

    file = fopen(p , "w+");
    BN_print_fp(file, n_safe);
    fprintf(file, "\n");
    BN_print_fp(file, d_safe);
    fclose(file);

    std::cout << "Key " << key_length << " generated" << std::endl << std::endl;

    BN_free(n_safe);
    BN_free(d_safe);
    BN_free(e_safe);
}

void bserver::generate_weak_keys(int key_length, char *path_to_save) {
    // Measure elapsed time
    auto start = std::chrono::high_resolution_clock::now();

//    Obliczamy wartość n = pq
//    Obliczamy wartość funkcji Eulera dla n: φ ( n ) = ( p − 1 ) ( q − 1 )
//    Wybieramy liczbę e (1 < e < φ(n)) względnie pierwszą z φ(n)
//    Znajdujemy liczbę d, gdzie jej różnica z odwrotnością liczby e jest podzielna przez φ(n) :
//
//    d ≡ e−1 (mod φ(n))
    //TODO
    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();
    BIGNUM *d_weak = BN_new();
    BIGNUM *e_weak = BN_new();
    BIGNUM *n_weak = BN_new();
    BIGNUM *euler = BN_new();
    BIGNUM *max = BN_new();
    BIGNUM *max_4 = BN_new();
    BIGNUM *zero = BN_new();
    BIGNUM *div = BN_new();

    BN_set_word(zero, 0);
    do {
        std::cout << "Generate primes" << std::endl;
        BN_generate_prime_ex(prime1, key_length / 2, 0, NULL, NULL, NULL);
        BN_generate_prime_ex(prime2, key_length / 2, 0, NULL, NULL, NULL);
        BN_mul(n_weak, prime1, prime2, ctx);

        max = find_max_factorial(prime1);
        BN_mul(max_4, max, max, ctx);
        BN_mul(max_4, max_4, max, ctx);
        BN_mul(max_4, max_4, max, ctx);
        BN_div(div, NULL, max_4, n_weak, ctx);
    }
    while(BN_cmp(div, zero) > 0);

    std::cout << "Prime1: " << BN_bn2dec(prime1) << " is safe: " << check_if_strong_prime(prime1) << std::endl;
    std::cout << "Prime2: " << BN_bn2dec(prime2) << " is safe: " << check_if_strong_prime(prime2) << std::endl;
    std::cout << BN_bn2dec(n_weak) << " <== N" << std::endl;
    std::cout << BN_bn2dec(max_4) << " <== Max^4" << std::endl;

    BIGNUM *one = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();
    BN_set_word(one, 1);

    BN_sub(temp1, prime1, one);
    BN_sub(temp2, prime2, one);
    BN_mul(euler, temp1, temp2, ctx);

    BIGNUM *gcd = BN_new();
    BN_one(one);

    do {
        BN_rand_range(e_weak, euler);
        BN_gcd(gcd, e_weak, euler, ctx);
    }
    while(BN_cmp(gcd, one) != 0);

    BN_mod_inverse(d_weak, e_weak, euler, ctx);

    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Generate " << key_length << " keys time: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count() << "ms" << std::endl;

    //free
    BN_free(gcd);
    BN_free(one);
    BN_free(temp1);
    BN_free(temp2);
    BN_free(euler);
    BN_free(max);
    BN_free(max_4);
    BN_free(div);
    BN_free(zero);

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
    BN_print_fp(file, n_weak);
    fprintf(file, "\n");
    BN_print_fp(file, e_weak);
    fclose(file);

    // Save private key
    memset(p, 0, sizeof p);
    strcat(p, path_to_save);
    strcat(p, "private");
    strcat(p, length);

    file = fopen(p , "w+");
    BN_print_fp(file, n_weak);
    fprintf(file, "\n");
    BN_print_fp(file, d_weak);
    fclose(file);

    std::cout << "Key " << key_length << " generated" << std::endl << std::endl;

    BN_free(n_weak);
    BN_free(e_weak);
    BN_free(d_weak);
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
    auto start = std::chrono::high_resolution_clock::now();

    BIGNUM *result = BN_new();
    BN_mod_exp(result, msg_to_sign, d, N, ctx);

    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Signing time: ";
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count() << "ms" << std::endl;

    char *ret = BN_bn2hex(result);
    BN_free(result);
    return ret;
}

bool bserver::check_if_strong_prime(BIGNUM *prime) {
    //condition: prime = 2*q+1

    BIGNUM *one = BN_new();
    BN_set_word(one, 1);

    BN_sub(prime, prime, one);
    BN_add(one, one, one);
    BN_div(prime, NULL, prime, one, ctx);

    int ret = BN_is_prime_fasttest_ex(prime, BN_prime_checks, ctx, 1, NULL);

    BN_free(one);
    if(ret == 0)
        return false;
    return true;
}

BIGNUM* bserver::find_max_factorial(BIGNUM *number) {
    BIGNUM *z = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *rem = BN_new();
    BN_set_word(one, 1);
    BN_set_word(z, 2);
    std::vector<BIGNUM*> factorials;

    BN_sub(number, number, one);

    BIGNUM *power = BN_new();
    BN_mul(power, z, z, ctx);

    // z^2 <= number
    while(BN_cmp(number, power) >= 0) {
        BN_div(NULL, rem, number, z, ctx);
        if(BN_is_zero(rem)) {
            factorials.push_back(BN_dup(z));
            BN_div(number, NULL, number, z, ctx);
        }
        else {
            BN_add(z, z, one);
        }
        BN_mul(power, z, z, ctx);
    }

    if(BN_cmp(number, one) == 1) {
        factorials.push_back(number);
    }

    // Find max factorial
    BIGNUM *max = BN_new();
    BN_set_word(one, 1);
    BN_set_word(max, 1);

    for(int i = 0; i < factorials.size(); i++) {
        if(BN_cmp(factorials.at(i), max) == 1) {
            max = BN_dup(factorials.at(i));
        }
    }

    //free
//    for(int i = 0; i < factorials.size(); i++)
//        BN_free(factorials.at(i));

    BN_free(rem);
    BN_free(z);
    BN_free(power);
    BN_free(one);

    return max;
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