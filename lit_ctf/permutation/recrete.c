#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    puts("You win!");
}

void fail(char *param_1) {
    puts(param_1);
    exit(1);
}

int is_permutation(char *param_1) {
    int local_2c;
    int seen[4] = {0};  // 0,1,2,3 must each appear exactly once
    
    for (local_2c = 0; local_2c < 4; local_2c++) {
        if (param_1[local_2c] < 0 || param_1[local_2c] > 3) {
            return 0;
        }
        if (seen[(int)param_1[local_2c]] != 0) {
            return 0;
        }
        seen[(int)param_1[local_2c]] = 1;
    }
    return 1;
}

int main(void) {
    int iVar1;
    int local_14;
    int local_10;
    int local_c;

    char a[0x18 * 4];  // 24 arrays, each 4 bytes
    char *ptrs[0x18];

    // Fill ptrs with offsets
    for (local_14 = 0; local_14 < 0x18; local_14++) {
        ptrs[local_14] = a + (long)local_14 * 4;
    }

    // Instead of reading input, generate 24 valid permutations of {0,1,2,3}
    char perms[24][4] = {
        {0,1,2,3}, {0,1,3,2}, {0,2,1,3}, {0,2,3,1},
        {0,3,1,2}, {0,3,2,1}, {1,0,2,3}, {1,0,3,2},
        {1,2,0,3}, {1,2,3,0}, {1,3,0,2}, {1,3,2,0},
        {2,0,1,3}, {2,0,3,1}, {2,1,0,3}, {2,1,3,0},
        {2,3,0,1}, {2,3,1,0}, {3,0,1,2}, {3,0,2,1},
        {3,1,0,2}, {3,1,2,0}, {3,2,0,1}, {3,2,1,0}
    };

    // Copy into a[] memory
    for (local_14 = 0; local_14 < 0x18; local_14++) {
        memcpy(ptrs[local_14], perms[local_14], 4);
    }

    // Print them so user can see
    for (local_14 = 0; local_14 < 0x18; local_14++) {
        printf("Permutation %2d: [%d %d %d %d]\n", local_14,
               ptrs[local_14][0], ptrs[local_14][1],
               ptrs[local_14][2], ptrs[local_14][3]);
    }

    // Validation loop (same as original logic)
    for (local_10 = 0; local_10 < 0x18; local_10++) {
        for (local_c = 0; local_c < local_10; local_c++) {
            iVar1 = memcmp(ptrs[local_10], ptrs[local_c], 4);
            if (iVar1 == 0) {
                printf("your match\n");
                fail("two arrays are the same");
            }
        }
        iVar1 = is_permutation(ptrs[local_10]);
        if (iVar1 == 0) {
            printf("your nonpermutation\n");
            fail("not a permutation!");
        }
    }

    printf("you did it\n");
    win();
    return 0;
}
