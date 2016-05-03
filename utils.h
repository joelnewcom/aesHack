#ifndef MPC_AES128_UTILS_HEADER_FILE
#define MPC_AES128_UTILS_HEADER_FILE

//****************************************************************************/
// MPC-project FS2016
// Purpose: utilities for AES attacke
// File:    utils.h
// Author:  M. Thaler, ZHAW, 2/2016
//****************************************************************************/
// fill input data into buffer -> buffer size multiple of 16 (128 bit)
// *len = 0 -> read input file and return pointer to buffer, str: filename
// *len > 0 -> copy str into buffer 
// returns size of buffer
//         actual length in len

int getData(uint8_t **buffer, const char *str, int *len);

//******************************************************************************

#endif
