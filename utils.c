//****************************************************************************/
// MPC-project FS2016
// Purpose: utilities for AES attacke
// File:    utils.h
// Author:  M. Thaler, ZHAW, 2/2016
//****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//******************************************************************************
// fill input date into buffer -> buffer size multiple of 16 (128 bit)
// *len = 0 -> read input file and return pointer to buffer, str: filename
// *len > 0 -> copy str into buffer 
// returns size of buffer
//         actual length in len

int getData(uint8_t **buffer, const char *str, int *len) {
    int     dlen, alen, fd;
    uint8_t *lbuf;
    assert(len != NULL);
    if (*len == 0) {
        fd   = open(str, O_RDONLY);
        assert(fd > 0);
        dlen = alen = lseek(fd, 0, SEEK_END); 
        lseek(fd, 0, SEEK_SET);   
    }
    else {
        dlen = alen = strlen(str);  
    }
    int diff = 16 - dlen % 16; 
    if (diff < 16)
        dlen   = dlen + diff;

    lbuf = (uint8_t *)malloc(dlen*sizeof(uint8_t)); 

    if (*len == 0) {
       int rlen = read(fd, (void*)lbuf, alen); 
       assert(rlen == alen);
    }
    else
        strncpy(lbuf, str, alen);
    *len = alen;
    *buffer = lbuf;
    return dlen; 
}

//******************************************************************************
