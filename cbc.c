//****************************************************************************/
// MPC-project FS2016
// Purpose: CBC-AES128 encryption / decryption
// File:    cbc.c
// Author:  M. Thaler, ZHAW, 2/2016
//****************************************************************************/

#include <stdint.h>
#include <stdio.h>
//#include <stdlib.h>
#include "string.h"
#include "cbc.h"
#include "aes128.h"

#define KEYLEN 16



// encrypt, CBC mode ----------------------------------------------------------

void encryptCBC(uint8_t *in, uint8_t *out, int dlen, uint8_t *key, uint8_t *iv) {
    uint8_t expandedKey[176];
    // the expanded key must be passed to encryptAES128
    expandKey(expandedKey, key);
    // ...


    uintptr_t i;
    //uint8_t remainders = dlen % KEYLEN; /* Remaining bytes in the last non-full block */

    for (i = 0; i < dlen; i += KEYLEN) {
        BlockCopy(out, in);
        BlockXor(out, iv);

        encryptAES128(out, expandedKey);

        iv = out;
        in += KEYLEN;
        out += KEYLEN;
    }

    /*if (remainders) {
        BlockCopy(out, in);
        memset(out + remainders, 0, KEYLEN - remainders); //add 0-padding 
        encryptAES128(out, expandedKey);
    }*/
}

// decrypt, CBC mode ----------------------------------------------------------

void decryptCBC(uint8_t *in, uint8_t *out, int dlen, uint8_t *key, uint8_t *iv, int nTh) {
    uint8_t expandedKey[176];
    // the expanded key must be passed to decryptAES128
    expandKey(expandedKey, key);
    // ...

    uintptr_t i;
    //uint8_t remainders = dlen % KEYLEN; /* Remaining bytes in the last non-full block */

//#pragma omp parallel num_threads(nTh)
   {
//#pragma omp for
           for (i = 0; i < dlen; i += KEYLEN) {
            uint8_t* tempIn = in + i;
            uint8_t* tempOut = out + i;
			uint8_t* tempIv;
			if(i == 0){
				tempIv = iv;
			}
			else{
				tempIv = tempIn - KEYLEN;
			}

			BlockCopy(tempOut, tempIn);
            decryptAES128(tempOut, expandedKey);
            BlockXor(tempOut, tempIv);
        }
   }

    /*if (remainders) {
	printf("REMAINDERS :-(");
        BlockCopy(out, in);
        memset(out + remainders, 0, KEYLEN - remainders); // add 0-padding

        decryptAES128(out, expandedKey);
    }*/
}


// hack, CBC mode -------------------------------------------------------------

int64_t attackCBC(uint8_t *in, int dlen, uint8_t *key, uint8_t *iv, int64_t nKeys, int64_t keyOffset, int nTh) {
    uint8_t expandedKey[176];
    // the expanded key must be passed to decryptAES128
    expandKey(expandedKey, key);

    dlen = KEYLEN*3;

    //the valid text has 66% valid chars
    int treshHoldForValidChars = (int)dlen - (dlen/2);
    
    //printf("\n\ndlen: %i, CPUS: %i, treshHold: %i\n\n", dlen, nTh, treshHoldForValidChars);


    int go = 1;

    uint8_t testKey[16]= {0};    
    int startIndexOfThread=0;
    for (int j = 8; j < 16; j++) {
        testKey[j] = key[j];
    }
    int64_t* correctKey = (int64_t*)(&testKey);
    *correctKey = -1;
    int64_t* keyAdd;
    uint8_t* testKeyCopy;
    uint8_t* decrypted;
    #pragma omp parallel num_threads(nTh) private(testKeyCopy, keyAdd, decrypted)
    {
        
        //copy the key and decrpyted variable for each thread
        decrypted = malloc(dlen * sizeof (uint8_t));
        testKeyCopy = malloc(16 * sizeof(uint8_t));
        
        keyAdd = (int64_t*) memcpy(testKeyCopy, testKey, 16 * sizeof(uint8_t));

        (*keyAdd) += keyOffset;
        //critical code can only be executed by one thread at time 
        startIndexOfThread ++;
        (*keyAdd) += startIndexOfThread;

        int st;
        while ((*keyAdd) < nKeys && go) {
            decryptCBC(in, decrypted, dlen, testKeyCopy, iv, nTh);
            
            //int countedChars = countValidChars(decrypted, dlen, nTh);
            st =0;          
            for (int i = 0; i < dlen; i++) {
                // A = 65, z = 122
                st += ((decrypted[i] > 'A') & (decrypted[i] < 'z'));
            }
            if (st > treshHoldForValidChars){
                //printf("\n Thread (%i) KeyAdd(%i) decrypted Text", omp_get_thread_num(), *keyAdd);
                /*for (int k = 0; k < dlen; k++){
                    printf("%c", decrypted[k]);
                }*/
                
                //copy the key into a public variable
                memcpy(correctKey, keyAdd, sizeof(int64_t));
                go = 0;
            }

            (*keyAdd) += nTh;
        }
        //printf("\n Thread (%i) KeyAdd(%i)", omp_get_thread_num(), *keyAdd);
       
    }    
    
   return *correctKey;
    
}
// ----------------------------------------------------------------------------


/*int countValidChars(uint8_t* decrypted, int dlen, int nTh){
    int st =0;
    {
        for (int i = 0; i < dlen; i++) {
            // A = 65, z = 122
            st += ((decrypted[i] > 'A') & (decrypted[i] < 'z'));
        }
    }
    
    return st;
}

double calculateEntropy(uint8_t* decrypted, int dlen, int nTh) {
    int frequencies[256] = {0};

    #pragma omp parallel num_threads(nTh)
    {
        #pragma omp for
        for (int i = 0; i < dlen; i++) {
            frequencies[decrypted[i]]++;
        }
    }

    double entropy = 0;
    for (int i = 0; i < 256; i++) {
        double frequency = (frequencies[i] / (double) dlen);
        if (frequency > 0.0) {
            entropy -= frequency * (log2(frequency) / log2(2.0));
        }
    }

    return entropy;
}*/

void BlockCopy(uint8_t* output, uint8_t* input) {
    for (int i = 0; i < KEYLEN; ++i) {
        output[i] = input[i];
    }
}

void BlockXor(uint8_t* buf, uint8_t* iv) {
    
	for (int i = 0; i < KEYLEN; ++i) {
        buf[i] ^= iv[i];
    }
}


