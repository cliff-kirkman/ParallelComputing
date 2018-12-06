/*****************************************************************************/
/**       Program description:  A parallel brute algorithm used to crack    **/
/**                             a secure key, developed from openSSL        **/
/**                             libraies and MPI                            **/
/**       Author: Cliff Kirkman                                             **/
/**       Last modified: 4/12/2018                                          **/
/*****************************************************************************/
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include <mpi.h>

#define ENCRYPT 0
#define DECRYPT 1
using namespace std;
bool verbose = false;

void handleOpenSSLErrors(void) {
    if (verbose) {
        ERR_print_errors_fp(stderr);
    }
}

/*  
 * Generic function designed to encrypt or decrypt text using openssl library functions,
 * caller choses encrypt or decrypt mode, failures are checked for at each step and handled by
 * handleOpenSSLErrors
 */
void encrypt_decrypt(unsigned char* input_text,
            unsigned char* key,
            unsigned char* iv,
            unsigned char* output_text,
            bool mode) {

    EVP_CIPHER_CTX* ctx;
    int len;
    int outputtext_len;
    int inputtext_len = strlen((char*)input_text);

    // Create and initialise the context 
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleOpenSSLErrors();

    if (mode == ENCRYPT) {
        // Initialise the encryption operation
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            handleOpenSSLErrors();

        // Provide the message to be encrypted 
        if (1 != EVP_EncryptUpdate(ctx, output_text, &len, input_text, inputtext_len))
            handleOpenSSLErrors();
        outputtext_len = len;

        // Finalise the encryption 
        if (1 != EVP_EncryptFinal_ex(ctx, output_text + len, &len))
            handleOpenSSLErrors();
        outputtext_len += len;
    } else if (mode == DECRYPT) {
        // Initialise the decryption operation
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
            handleOpenSSLErrors();

        // Provide the message to be decrypted 
        if (1 != EVP_DecryptUpdate(ctx, output_text, &len, input_text, inputtext_len))
            handleOpenSSLErrors();
        outputtext_len = len;

        // Finalise the decryption 
        if (1 != EVP_DecryptFinal_ex(ctx, output_text + len, &len))
            handleOpenSSLErrors();
        outputtext_len += len;
    } else {
        std::cerr << "Invalid mode chosen, must be ENCRYPT or DECRYPT" << std::endl;
    }

    EVP_CIPHER_CTX_free(ctx);
    output_text[outputtext_len] = '\0';
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "-v")) {
        verbose = true;
    }

    // initialization start
    unsigned char* unencrypted_text = (unsigned char*) "This is a top secret.";
    unsigned char* key = (unsigned char*) "#####abp01!#####";
    unsigned char encrypted_text[128];
    unsigned char decrypted_text[128];
    unsigned char attempt_key[] = "#####xxxxxx#####";
    unsigned char* iv = (unsigned char*) "010203040506070809000a0b0c0d0e0f";
    bool found = false;
    // Start timer
    clock_t begin = clock();
    MPI_Init(&argc, &argv);
    int numnodes, nid;
    char processor_name[MPI_MAX_PROCESSOR_NAME];
    int name_len;
    // initialization end

    MPI_Get_processor_name(processor_name, &name_len);
    MPI_Comm_size(MPI_COMM_WORLD, &numnodes);
    MPI_Comm_rank(MPI_COMM_WORLD, &nid);

    std::cout << "MPI processor name: " << processor_name << std::endl;
    std::cout << "MPI size: " << numnodes << endl;
    std::cout << "MPI nid: " << nid << endl;
    // Encrpt unencrypted_text
    encrypt_decrypt(unencrypted_text, key, iv, encrypted_text, ENCRYPT);

    // Populate range of ascii character set excluding delete and space
    unsigned char* ascii = (unsigned char*) "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[]^_`{|}~";

    // Find size of character set
    int size = strlen((char*) ascii);

    // Synchronize all threads
    MPI_Barrier(MPI_COMM_WORLD);

    // Started from 5th position since simplified key uses hash as first and last five characters
    // Search through all possible six letter combinations trying to decrypt each one
    for (int nid; nid < size; nid += numnodes) {
        if (verbose) {
            cout << "MPI nid: " << nid << " is searching through: " << ascii[nid] << endl;
        }
        attempt_key[5] = ascii[nid];
        for (int j = 0; j < size; j++) {
            attempt_key[6] = ascii[j];
            for (int k = 0; k < size; k++) {
                attempt_key[7] = ascii[k];
                for (int l = 0; l < size; l++) {
                    attempt_key[8] = ascii[l];
                    for (int m = 0; m < size; m++) {
                        attempt_key[9] = ascii[m];
                        for (int n = 0; n < size; n++) {
                            if (found)
                                goto end;
                            attempt_key[10] = ascii[n];
                            encrypt_decrypt(encrypted_text,
                                             attempt_key, iv, decrypted_text, DECRYPT);
                            if (!strcmp((char *)unencrypted_text, (char *)decrypted_text)) {
                                found = true;
                                // Calculate and output time spent
                                clock_t end = clock();
                                double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
                                cout << "Time spent: " << time_spent << endl;
                                cout << "Sucessful key is: " << attempt_key << endl;
                                cout << "Decrypted_text is: " << decrypted_text << endl;
                                goto end;
                            }
                        }
                    }
                }
            }
        }
    }
    end: MPI_Barrier(MPI_COMM_WORLD);
    MPI_Finalize();

    return 0;
}