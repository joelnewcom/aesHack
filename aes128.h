#ifndef MPC_AES128_HEADER_FILE
#define MPC_AES128_HEADER_FILE

//****************************************************************************/
// MPC-project FS2016
// Purpose: AES128 encryption / decryption
// File:    aes128.h
// Author:  C-Code by Kristian, Laurent Haan,
//          www.codeplanet.eu/tutorials/cpp/51-advanced-encryption
// Author:  in-line Assembler by M. Thaler, ZHAW, 2/2016
//****************************************************************************/

#include <stdint.h>

// assumes input, output and key to be 16 bytes long

void expandKey(uint8_t* expandedKey, uint8_t* cipherKey);
void encryptAES128(const uint8_t* state, uint8_t *expandedKey);
void decryptAES128(const uint8_t* state, uint8_t *expandedKey);

#endif
