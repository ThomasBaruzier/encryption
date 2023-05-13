#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#define ITERATIONS 100000
#define KEY_SIZE 32
#define SALT_SIZE 8
#define MAX_LEN 1024*32

int has_extension(const char *filename, const char *ext) {
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return 0;
    return strcmp(dot + 1, ext) == 0 ? 1 : 0;
}

void str_encode(const char* in, char** out, const char* password, int iterations) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    RAND_bytes(salt, SALT_SIZE);
    PKCS5_PBKDF2_HMAC(password, -1, salt, SALT_SIZE, iterations, EVP_sha512(), KEY_SIZE, key);
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    int inlen = strlen(in);
    unsigned char* inbuf = malloc(inlen);
    memcpy(inbuf, in, inlen);

    int outlen, tmplen;
    unsigned char* outbuf = malloc(inlen + EVP_MAX_IV_LENGTH);
    EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
    EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, salt, SALT_SIZE);
    BIO_write(b64, iv, EVP_MAX_IV_LENGTH);
    BIO_write(b64, outbuf, outlen);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    *out = malloc(bptr->length + 1);
    memcpy(*out, bptr->data, bptr->length);
    (*out)[bptr->length] = '\0';
    BIO_free_all(b64);
    free(inbuf); free(outbuf);
}

int str_decode(const char* in, char** out, const char* password, int iterations) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf((void*)in, -1);
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_read(b64, salt, SALT_SIZE);
    BIO_read(b64, iv, EVP_MAX_IV_LENGTH);
    unsigned char* inbuf = malloc(strlen(in));
    int inlen = BIO_read(b64, inbuf, strlen(in));
    BIO_free_all(b64);

    PKCS5_PBKDF2_HMAC(password, -1, salt, SALT_SIZE, iterations, EVP_sha512(), KEY_SIZE, key);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int outlen, tmplen;
    unsigned char* outbuf = malloc(inlen);
    unsigned char* tmpbuf = malloc(inlen);
    memcpy(tmpbuf, inbuf, inlen);

    if (EVP_DecryptUpdate(ctx, outbuf, &outlen, tmpbuf, inlen) != 1) {
        free(inbuf); free(outbuf); free(tmpbuf);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen) != 1) {
        free(inbuf); free(outbuf); free(tmpbuf);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    outlen += tmplen;
    *out = malloc(outlen + 1);
    memcpy(*out, outbuf, outlen);
    (*out)[outlen] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    free(inbuf); free(outbuf); free(tmpbuf);
    return 0;
}

void get_output_path(char *output) {
    int last = strlen(output) - 1;
    for (int i = last; i > 0 && output[i] != '/'; i--) {
        if (output[i] == '.') {
            output[i+1] = 'b'; output[i+2] = 'i';
            output[i+3] = 'n'; output[i+4] = '\0';
            return;
        }
    }
    strcat(output, ".bin");
}

void handle_file_mode(const char *password, char *path) {
    int last = strlen(path) - 1;
    for (int i = last; path[last] == '/'; i--) { path[last] = '\0'; last--; }

    char command[MAX_LEN];
    char basedir[PATH_MAX], filename[PATH_MAX], output[PATH_MAX];
    strcpy(basedir, path); strcpy(output, path); strcpy(filename, path);

    dirname(basedir);
    strcpy(filename, basename(filename));
    get_output_path(output);

    if (has_extension(path, "bin")) {
        if (strcmp(filename, path) != 0) {
            snprintf(command, MAX_LEN, "openssl enc -aes-256-cbc -d -pass pass:\"%s\" -pbkdf2 -md sha512 -in \"%s\" | tar -C \"%s\" -xf -", password, path, basedir);
        } else {
            snprintf(command, MAX_LEN, "openssl enc -aes-256-cbc -d -pass pass:\"%s\" -pbkdf2 -md sha512 -in \"%s\" | tar -xf -", password, path);
        }
    } else if (strcmp(filename, path) != 0) {
        snprintf(command, MAX_LEN, "tar -C \"%s\" -cf - \"%s\" | openssl enc -aes-256-cbc -salt -pass pass:\"%s\" -pbkdf2 -md sha512 -out \"%s\"", basedir, filename, password, output);
    } else {
        snprintf(command, MAX_LEN, "tar -cf - \"%s\" | openssl enc -aes-256-cbc -salt -pass pass:\"%s\" -pbkdf2 -md sha512 -out \"%s\"", filename, password, output);
    }

    system(command);
}


int handle_string_mode(const char *password, int path_pos, int argc, char **argv) {
    char *encoded = NULL;
    char *decoded = NULL;
    char input[MAX_LEN];

    if (path_pos != 0) {
        FILE *file = fopen(argv[path_pos], "r");
        if (file) {
            size_t n = fread(input, 1, sizeof(input) - 1, file);
            input[n] = '\0';
            fclose(file);
        } else {
            printf("Error: File not found\n");
        }
    } else if (argc >= 2) {
        strcpy(input, argv[1]);
    } else {
        printf("String: ");
        fgets(input, MAX_LEN, stdin);
        input[strcspn(input, "\n")] = '\0';
    }

    if (str_decode(input, &decoded, password, ITERATIONS) == 0) {
        printf("Decoded string: %s\n", decoded);
        free(decoded);
    } else {
        str_encode(input, &encoded, password, ITERATIONS);
        printf("Encoded string: %s\n", encoded);
        free(encoded);
    }

    return 0;
}

void helper(char *pgrm_name) {
    printf("Usage: %s {OPTIONS} [FILE|STRING]\n", pgrm_name);
    printf("\nOptions:\n");
    printf("  -h, --help    Show this help message and exit\n");
    printf("  -s, --string  Treat any file as its content\n");
    printf("\n");
}

int main(int argc, char **argv) {
    int string_mode = 0, path_pos = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            helper(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--string") == 0) {
            string_mode = 1;
        } else if (!access(argv[i], F_OK)) {
            path_pos = i;
        }
    }

    if (string_mode == 1 && path_pos == 0) {
        printf("Error: String mode activated, but no files given.\n");
        helper(argv[0]);
        return 1;
    }

    char *password = getpass("Password: ");
    if (path_pos == 0 || string_mode == 1) {
        return handle_string_mode(password, path_pos, argc, argv);
    } else {
        handle_file_mode(password, argv[path_pos]);
    }

    return 0;
}
