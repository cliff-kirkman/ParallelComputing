/*****************************************************************************/
/**       Program description:  A parallel brute algorithm used to crack    **/
/**                             a secure key, developed from openSSL        **/
/**                             libraies and openMP                         **/
/**       Author: Cliff Kirkman                                             **/
/**       Last modified: 4/12/2018                                          **/
/*****************************************************************************/

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include <omp.h>

#define ENCRYPT 0
#define DECRYPT 1
#define NUMBEROFTHREADS 4
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



int main(int argc, char const *argv[])
{
    if (argc >= 2 && !strcmp(argv[1], "-v")) {
        verbose = true;
    }

    // initialization start
    unsigned char* unencrypted_text = (unsigned char*) "This is a top secret.";
    unsigned char* key = (unsigned char*) "#####abp01!#####";
    unsigned char encrypted_text[128];
    unsigned char* iv = (unsigned char*) "010203040506070809000a0b0c0d0e0f";
    // initialization end

    // Encrpt unencrypted_text
    encrypt_decrypt(unencrypted_text, key, iv, encrypted_text, ENCRYPT);

    // Populate range of ascii character set excluding delete and space
    unsigned char* ascii = (unsigned char*) "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()*+,-./:;<=>?@[]^_`{|}~";

    // Find size of character set
    int size = strlen((char*) ascii);
    // Start timer
    bool found = false;
    clock_t begin = clock();

    // Started from 5th position since simplified key uses hash as first and last five characters
    // Search through all possible six letter combinations trying to decrypt each one
    #pragma omp parallel num_threads(NUMBEROFTHREADS)
    {
        // initialization start for private thread variables
        int tid = omp_get_thread_num();
        unsigned char p_encrypted_text[128];
        //copy original encrypted text to private version
        memcpy(p_encrypted_text, encrypted_text, strlen((char*)encrypted_text)+1);
        // To aviod memory sharing copys have been created to speed up the process
        unsigned char attempt_key[] = "#####xxxxxx#####";
        unsigned char decrypted_text[128];
        // initialization end for private thread variables

        // id number for print out, only used in verbose mode
        int print_id = tid;

        // Each thread starts from a different character e.g. thread 0 starts at a and tries all
        // possible combinations beneath a, thread 1 starts at b and does the same
        // if combination hasn't been found thread 0 moves to e thread 1 moves to f and so on
        for (tid; tid < size; tid += NUMBEROFTHREADS) {
            // Check thread doesn't increment past the end of the array
            if (size < tid)
                goto end;
            attempt_key[5] = ascii[tid];
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
                                if (verbose) {
                                    cout << "Attemped key generated by " << print_id << " is " << attempt_key << endl;
                                }
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
                                }
                            }
                        }
                    }
                }
            }
        }
        end: ;
        #pragma omp barrier
    }
    return 0;
}