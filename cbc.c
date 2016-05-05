//****************************************************************************/
// MPC-project FS2016
// Purpose: CBC-AES128 encryption / decryption
// File:    cbc.c
// Author:  M. Thaler, ZHAW, 2/2016
//****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <inttypes.h>


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
    uint8_t remainders = dlen % KEYLEN; /* Remaining bytes in the last non-full block */

    for (i = 0; i < dlen; i += KEYLEN) {
        BlockCopy(out, in);
        BlockXor(out, iv);

        encryptAES128(out, expandedKey);

        iv = out;
        in += KEYLEN;
        out += KEYLEN;
    }

    if (remainders) {
        BlockCopy(out, in);
        memset(out + remainders, 0, KEYLEN - remainders); /* add 0-padding */
        encryptAES128(out, expandedKey);
    }
}

// decrypt, CBC mode ----------------------------------------------------------

void decryptCBC(uint8_t *in, uint8_t *out, int dlen, uint8_t *key, uint8_t *iv, int nTh) {
    uint8_t expandedKey[176];
    // the expanded key must be passed to decryptAES128
    expandKey(expandedKey, key);
    // ...

    uintptr_t i;
    uint8_t remainders = dlen % KEYLEN; /* Remaining bytes in the last non-full block */

#pragma omp parallel num_threads(nTh)
   {
#pragma omp for
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

    if (remainders) {
		printf("REMAINDERS :-(");
        BlockCopy(out, in);
        memset(out + remainders, 0, KEYLEN - remainders); /* add 0-padding */

        decryptAES128(out, expandedKey);
    }
}


// hack, CBC mode -------------------------------------------------------------

int64_t attackCBC(uint8_t *in, int dlen, uint8_t *key, uint8_t *iv, int64_t nKeys, int64_t keyOffset, int nTh) {
    uint8_t expandedKey[176];
    // the expanded key must be passed to decryptAES128
    expandKey(expandedKey, key);
    // ...  

    dlen = KEYLEN*3;
    

    int64_t i, j;
    uint8_t* decrypted = (uint8_t *) malloc(dlen * sizeof (uint8_t));

    uint8_t testKey[16] = {0};

    for (i = 8; i < 16; i++) {
        testKey[i] = key[i];
    }

    int64_t* keyAdd = (int64_t*) (&testKey);

    //the valid text has 80% valid chars
    int treshHoldForValidChars = (int)dlen - (dlen/5);
    
    printf("\n\ndlen: %i, CPUS: %i, treshHold: %i\n\n", dlen, nTh, treshHoldForValidChars);
    (*keyAdd) += keyOffset;
    int give = 0;
    int go = 1;
    
    #pragma omp parallel num_threads(nTh)
    {
        uint start, stop;
        
        #pragma omp critical
        {
            start = give;
            give += nKeys/omp_get_num_threads();
            stop = give;

            if(omp_get_thread_num() == omp_get_num_threads()-1)
                stop = nKeys;
        }
        
        while (start < stop && go) {
   
            decryptCBC(in, decrypted, dlen, testKey, iv, nTh);

            int countedChars = countValidChars(decrypted, dlen, nTh);
            //double entropy = calculateEntropy(decrypted, dlen, nTh);

           //if (entropy <= 4.3) {

            if (countedChars > treshHoldForValidChars){
                //printf("KEY FOUND!!!Entropy:  (%f) Tested Key:\n", entropy);

                /*printf("\n decrypted Text: ");

                for (int k = 0; k < dlen; k++){
                    printf("%c", decrypted[k]);
                }*/

                
                    go = 0;

            }
            #pragma omp atomic
            start++;
            #pragma omp atomic
            (*keyAdd)++;
            
        }
    }    
        
    
    if (!go){
        return (*keyAdd);
    }else{
        return -1;
    }
    
}
// ----------------------------------------------------------------------------


int countValidChars(uint8_t* decrypted, int dlen, int nTh){
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
}

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


