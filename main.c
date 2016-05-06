#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <omp.h>

#include "cbc.h"
#include "utils.h"
#include <inttypes.h>
#include <limits.h>
//******************************************************************************

int main(int argc, char *argv[]) {
    int nTh = 1, len, alen;
    double dt;
    uint8_t *in, *out, *inout;
    //uint8_t key[16] = {0};
    uint8_t key[16] = {
        11, 2, 10, 0, 0, 0, 0, 0,
        35, 123, 7, 3, 7, 1, 9, 34
	};
    
    uint8_t iv[16] = {0x80, 0x01, 0x80, 0x01, 0x80, 0x01, 0x80, 0x01,
        0x80, 0x01, 0x80, 0x01, 0x80, 0x01, 0x80, 0x01};

    if (argc > 1)
        nTh = atoi(argv[1]);

    // encrypt / decrypt: function test -------------------------------------
    alen = 1;
    uint8_t *str = (uint8_t *) "Ubi DADA, ibi bene";

    len = getData(&in, str, &alen);
    inout = (uint8_t *) malloc(len * sizeof (uint8_t));
    out = (uint8_t *) malloc(len * sizeof (uint8_t));

    encryptCBC(in, inout, len, key, iv);
    decryptCBC(inout, out, len, key, iv, 1);

    for (int i = 0; i < alen; i++)
        assert(out[i] == in[i]);

    for (int i = 0; i < alen; i++)
        printf("%c", out[i]);
    printf("\n");

    free(in);
    free(out);
    free(inout);

    // encrypt / decrypt: speed test ----------------------------------------

    alen = 0;
    len = getData(&in, "dada.dat", &alen);

    inout = (uint8_t *) malloc(len * sizeof (uint8_t));
    out = (uint8_t *) malloc(len * sizeof (uint8_t));

    // "heat" CPU
    for (int i = 0; i < 10; i++) {
        encryptCBC(in, inout, len, key, iv);
        decryptCBC(inout, out, len, key, iv, nTh);
    }

    // now measure time
    encryptCBC(in, inout, len, key, iv);

    dt = omp_get_wtime();
    decryptCBC(inout, out, len, key, iv, nTh);
    dt = omp_get_wtime() - dt;

    for (int i = 0; i < alen; i++)
        assert(out[i] == in[i]);
    printf("\n");

    printf("Speedtest done: %2.2lf ms CPUs(%d)\n", 1000.0 * dt, nTh);
    free(in);
    free(out);
    free(inout);

    // encrypt / decrypt: cracker ----------------------------------------

    alen = 0;
    //len = getData(&in, "test.txt", &alen);
    len = getData(&in, "dada.dat", &alen);
    inout = (uint8_t *) malloc(len * sizeof (uint8_t));
    out = (uint8_t *) malloc(len * sizeof (uint8_t));

    encryptCBC(in, inout, len, key, iv);
    int keyOffset = 0;
    printf("\nstart crackin:\n");
    dt = omp_get_wtime();
    int64_t crackedKey = attackCBC(inout, len, key, iv, 2147483647, keyOffset, nTh);
    dt = omp_get_wtime() - dt;
    //2147483647
    printf("\nkeys per second: %f\n", crackedKey/dt);
    printf("\nCracked Elapsed: %2.2lf ms CPUs(%d)\n", 1000.0 * dt, nTh);
    
    printf("\nfound key: %" PRId64 "\n", crackedKey);

    //hackCBC(inout, out, dlen, key, iv, 1024, nTh);
    //hackCBC(inout, out, dlen, key, iv, 1024, nTh);
    free(in);
    free(out);
    free(inout);
}
