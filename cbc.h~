#ifndef MPC_CBC_HEADER_FILE
#define MPC_CBC_HEADER_FILE

//****************************************************************************/
// MPC-project FS2016
// Purpose: CBC-AES128 encryption / decryption
// File:    cbc.h
// Author:  M. Thaler, ZHAW, 2/2016
//****************************************************************************/

#include <stdint.h>

#include "cbc.h"
#include "aes128.h"


// encrypt, CBC mode ----------------------------------------------------------

void encryptCBC(uint8_t *in, uint8_t *out, int dlen, uint8_t *key, uint8_t *iv);

// decrypt, CBC mode ----------------------------------------------------------

void decryptCBC(uint8_t *in, uint8_t *out, int dlen,
        uint8_t *key, uint8_t *iv, int nTh);

// attack, CBC mode -----------------------------------------------------------

int64_t attackCBC(uint8_t *in, int dlen, uint8_t *key, uint8_t *iv,
        int64_t nKeys, int64_t keyOffset, int nTh);

// ----------------------------------------------------------------------------

void BlockCopy(uint8_t* output, uint8_t* input);

void BlockXor(uint8_t* buf,uint8_t* iv);

double calculateEntropy(uint8_t* decrypted, int dlen);


#endif

