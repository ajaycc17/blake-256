// Invert a G function and preimage attack on 1.5 round of BLAKE-256
// here the guesses used are the original messages as the original algorithm with word-guessing
// has the time complexity of 2^128
// reference paper: https://eprint.iacr.org/2010/043 (section 5)
#include "../blake_header.h"

// attack function - takes initial input and final states as input and returns the original message as output
uint32_t *preimage_attack(uint32_t v0[], uint32_t v1_5[], uint32_t m8, uint32_t m10, uint32_t m11, uint32_t v10)
{
    // states after 0.5 and 1 round, initialize with 0
    uint32_t state0_5[16] = {0}, state1[16] = {0};
    static uint32_t pred_mess[16] = {0};

    // using 4th inversion eqn. determine (v4-v7) (after 1 round)
    state1[4] = ROTL(ROTL(v1_5[4], 7) ^ v1_5[8], 12) ^ (v1_5[8] - v1_5[12]);
    state1[5] = ROTL(ROTL(v1_5[5], 7) ^ v1_5[9], 12) ^ (v1_5[9] - v1_5[13]);
    state1[6] = ROTL(ROTL(v1_5[6], 7) ^ v1_5[10], 12) ^ (v1_5[10] - v1_5[14]);
    state1[7] = ROTL(ROTL(v1_5[7], 7) ^ v1_5[11], 12) ^ (v1_5[11] - v1_5[15]);

    // using 5th inversion eqn. determine (v8-v11) (after 1 round)
    state1[8] = v1_5[8] - v1_5[12] - (ROTL(v1_5[12], 8) ^ v1_5[0]);
    state1[9] = v1_5[9] - v1_5[13] - (ROTL(v1_5[13], 8) ^ v1_5[1]);
    state1[10] = v1_5[10] - v1_5[14] - (ROTL(v1_5[14], 8) ^ v1_5[2]);
    state1[11] = v1_5[11] - v1_5[15] - (ROTL(v1_5[15], 8) ^ v1_5[3]);

    // using 7th inversion eqn. determine v12 and v13 (after 1 round)
    state1[12] = ROTL((ROTL(v1_5[12], 8) ^ v1_5[0]), 16) ^ (v1_5[0] - (ROTL(v1_5[4], 7) ^ v1_5[8]) - m10);
    state1[13] = ROTL((ROTL(v1_5[13], 8) ^ v1_5[1]), 16) ^ (v1_5[1] - (ROTL(v1_5[5], 7) ^ v1_5[9]) - m8);

    // using 4th inversion eqn. determine v6 and v7 (after 0.5 round)
    state0_5[6] = ROTL(ROTL(state1[6], 7) ^ state1[11], 12) ^ (state1[11] - state1[12]);
    state0_5[7] = ROTL(ROTL(state1[7], 7) ^ state1[8], 12) ^ (state1[8] - state1[13]);

    // using 2nd inversion eqn. determine pred_mess[4] (after 0.5 round)
    pred_mess[4] = (ROTL(((ROTL((ROTL(state0_5[6], 7) ^ v10), 12) ^ v0[6]) - v0[10]), 16) ^ v0[14]) - v0[2] - v0[6];

    // using 2nd inversion eqn. determine v1 (after 1 round)
    state1[1] = (ROTL(((ROTL((ROTL(v1_5[5], 7) ^ v1_5[9]), 12) ^ state1[5]) - state1[9]), 16) ^ state1[13]) - state1[5] - pred_mess[4];

    // using 6th inversion eqn. determine v14 (after 0.5 round)
    state0_5[14] = v10 - v0[10] - ROT((v0[14] ^ (v0[2] + v0[6] + pred_mess[4])), 16);

    // using 3rd inversion eqn. determine v1 (after 0.5 round)
    state0_5[1] = state1[1] - (ROTL(state1[6], 7) ^ state1[11]) - m11 - state0_5[6] - m10;

    // using 5th inversion eqn. determine v11 (after 0.5 round)
    state0_5[11] = state1[11] - state1[12] - (ROTL(state1[12], 8) ^ state1[1]);

    // using 2nd inversion eqn. determine v12 (after 0.5 round)
    state0_5[12] = ROTL(((ROTL((ROTL(state1[6], 7) ^ state1[11]), 12) ^ state0_5[6]) - state0_5[11]), 16) ^ (state0_5[1] + state0_5[6] + m10);

    // using 5th inversion eqn. determine v2 (after 0.5 round)
    state0_5[2] = (v10 - state0_5[14] - v0[10]) ^ ROTL(state0_5[14], 8);

    // using 8th inversion eqn. determine pred_mess[5]
    pred_mess[5] = (ROTL(((ROTL((ROTL(state0_5[6], 7) ^ v10), 12) ^ v0[6]) - v0[10]), 16) ^ v0[14]) + (ROTL(state0_5[6], 7) ^ v10) - state0_5[2];
    pred_mess[5] = -pred_mess[5];

    // using 2nd inversion eqn. determine pred_mess[6]
    pred_mess[6] = (ROTL(((ROTL((ROTL(state0_5[7], 7) ^ state0_5[11]), 12) ^ v0[7]) - v0[11]), 16) ^ v0[15]) - v0[7] - v0[3];

    // using 7th inversion eqn. determine v15 (after 1 round)
    state1[15] = ROTL((ROTL(v1_5[15], 8) ^ v1_5[3]), 16) ^ (v1_5[3] - (ROTL(v1_5[7], 7) ^ v1_5[11]) - pred_mess[6]);

    // using 6th inversion eqn. determine v15 (after 0.5 round)
    state0_5[15] = state0_5[11] - v0[11] - ROT((v0[15] ^ (v0[3] + v0[7] + pred_mess[6])), 16);

    // using 4th inversion eqn. determine v5 (after 0.5 round)
    state0_5[5] = ROTL((ROTL(state1[5], 7) ^ state1[10]), 12) ^ (state1[10] - state1[15]);

    // using 5th inversion eqn. determine v0 (after 1 round)
    state1[0] = (state1[10] - state1[15] - v10) ^ ROTL(state1[15], 8);

    // using 8th inversion eqn. determine pred_mess[9]
    pred_mess[9] = (ROTL(((ROTL((ROTL(state1[5], 7) ^ state1[10]), 12) ^ state0_5[5]) - v10), 16) ^ state0_5[15]) + (ROTL(state1[5], 7) ^ state1[10]) - state1[0];
    pred_mess[9] = -pred_mess[9];

    // using 2nd inversion eqn. determine pred_mess[14]
    pred_mess[14] = (ROTL(((ROTL((ROTL(v1_5[4], 7) ^ v1_5[8]), 12) ^ state1[4]) - state1[8]), 16) ^ state1[12]) - state1[0] - state1[4];

    // using 5th inversion eqn. determine v3 (after 0.5 round)
    state0_5[3] = (state0_5[11] - state0_5[15] - v0[11]) ^ ROTL(state0_5[15], 8);

    // using 8th inversion eqn. determine pred_mess[7]
    pred_mess[7] = (ROTL(((ROTL((ROTL(state0_5[7], 7) ^ state0_5[11]), 12) ^ v0[7]) - v0[11]), 16) ^ v0[15]) + (ROTL(state0_5[7], 7) ^ state0_5[11]) - state0_5[3];
    pred_mess[7] = -pred_mess[7];

    // using 2nd inversion eqn. determine v0 (after 0.5 round)
    state0_5[0] = (ROTL(((ROTL((ROTL(state1[5], 7) ^ state1[10]), 12) ^ state0_5[5]) - v10), 16) ^ state0_5[15]) - m8 - state0_5[5];

    // using 5th inversion eqn. determine v8 (after 0.5 round)
    state0_5[8] = v0[8] + state0_5[12] + (ROTL(state0_5[12], 8) ^ state0_5[0]);

    // using 1st inversion eqn. determine pred_mess[0]
    pred_mess[0] = (ROTL((ROTL(state0_5[12], 8) ^ state0_5[0]), 16) ^ v0[12]) - v0[4] - v0[0];

    // using 5th inversion eqn. determine v2 (after 1 round)
    state1[2] = (state1[8] - state1[13] - state0_5[8]) ^ ROTL(state1[13], 8);

    // using 2nd inversion eqn. determine v14 (after 1 round)
    state1[14] = (state1[2] + pred_mess[9] + state1[6]) ^ ROTL(((ROTL((ROTL(v1_5[6], 7) ^ v1_5[10]), 12) ^ state1[6]) - state1[10]), 16);

    // using 8th inversion eqn. determine pred_mess[15]
    pred_mess[15] = (ROTL(((ROTL((ROTL(v1_5[6], 7) ^ v1_5[10]), 12) ^ state1[6]) - state1[10]), 16) ^ state1[14]) + (ROTL(v1_5[6], 7) ^ v1_5[10]) - v1_5[2];
    pred_mess[15] = -pred_mess[15];

    // using 9th inversion eqn. determine v4 (after 0.5 round)
    state0_5[4] = ROT((ROT((v0[4] ^ (state0_5[8] - state0_5[12])), 12) ^ state0_5[8]), 7);

    // using 8th inversion eqn. determine pred_mess[1]
    pred_mess[1] = (ROTL(((ROTL((ROTL(state0_5[4], 7) ^ state0_5[8]), 12) ^ v0[4]) - v0[8]), 16) ^ v0[12]) + (ROTL(state0_5[4], 7) ^ state0_5[8]) - state0_5[0];
    pred_mess[1] = -pred_mess[1];

    // using 6th inversion eqn. determine v9 (after 0.5 round)
    state0_5[9] = state1[9] - state1[14] - ROT((state0_5[14] ^ (state0_5[3] + state0_5[4] + pred_mess[14])), 16);

    // using 8th inversion eqn. determine v3 (after 1 round)
    state1[3] = (ROTL(((ROTL((ROTL(state1[4], 7) ^ state1[9]), 12) ^ state0_5[4]) - state0_5[9]), 16) ^ state0_5[14]) + (ROTL(state1[4], 7) ^ state1[9]) + pred_mess[15];

    // using 2nd inversion eqn. determine pred_mess[13]
    pred_mess[13] = (ROTL(((ROTL((ROTL(v1_5[7], 7) ^ v1_5[11]), 12) ^ state1[7]) - state1[11]), 16) ^ state1[15]) - state1[3] - state1[7];

    // using 2nd inversion eqn. determine pred_mess[2]
    pred_mess[2] = (ROTL(((ROTL((ROTL(state0_5[5], 7) ^ state0_5[9]), 12) ^ v0[5]) - v0[9]), 16) ^ v0[13]) - v0[1] - v0[5];

    // using 8th inversion eqn. determine pred_mess[3]
    pred_mess[3] = (ROTL(((ROTL((ROTL(state0_5[5], 7) ^ state0_5[9]), 12) ^ v0[5]) - v0[9]), 16) ^ v0[13]) + (ROTL(state0_5[5], 7) ^ state0_5[9]) - state0_5[1];
    pred_mess[3] = -pred_mess[3];

    // using 7th inversion eqn. determine v13 (after 0.5 round)
    state0_5[13] = ROTL((ROTL(state1[13], 8) ^ state1[2]), 16) ^ (state1[2] - (ROTL(state1[7], 7) ^ state1[8]) - pred_mess[13]);

    // using 2nd inversion eqn. determine pred_mess[12]
    pred_mess[12] = (ROTL(((ROTL((ROTL(state1[7], 7) ^ state1[8]), 12) ^ state0_5[7]) - state0_5[8]), 16) ^ state0_5[13]) - state0_5[2] - state0_5[7];

    return pred_mess;
}

// main function
int main()
{
    // for reference only *****************************************************
    // 32-bit messages - original messages - here the string message is "ajay1137"
    uint32_t m[16] = {0x616a6179, 0x31313337, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000, 0x00000040};

    // states after 0.5 round
    uint32_t v0_5[16] = {0x647d44cd, 0xdb008917, 0xd6081eed, 0xdeef5d0d, 0x70371426, 0x7b2d63f0, 0x0e0d2a75, 0x91f00a19, 0x0d43640f, 0x92228a3b, 0x7c806b57, 0x25bb9672, 0x46c640fc, 0xe5fd8176, 0x31e18d4d, 0x737035b0};

    // states after 1 round
    uint32_t v1[16] = {0x9bc0d2f4, 0xad8f25a2, 0x28ca6d45, 0x21765ad4, 0x8ee063f0, 0x31f7059f, 0xa28c146f, 0x7a6dcdca, 0xf634a103, 0xa27e1126, 0x4794e5af, 0x828b45c7, 0x695eff8a, 0x4080baef, 0x13dd0824, 0x2e06cd7e};
    // for reference only *****************************************************

    // initial states before any rounds i.e. v0, constants are used as counter t is not xored
    uint32_t v0[16] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, 0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093862, 0x299f3190, 0x082efa98, 0xec4e6c89};

    // final states given as input to the attack function
    uint32_t v1_5[16] = {0x99c44b0c, 0x3ab688fc, 0x70adbc8e, 0x021548b2, 0x45bba136, 0xf0ebcf2b, 0x08e49382, 0x6bbecba1, 0xb2f38f0a, 0x2ed7c843, 0xd71efb9e, 0xb954f0a6, 0xf350aa08, 0xfaab1817, 0x05f93d64, 0x50e7f4fd};

    // invoke the preimage function and pass the guessed messages to the function
    uint32_t *pred_m;
    pred_m = preimage_attack(v0, v1_5, m[8], m[10], m[11], v0_5[10]);

    // compare the original and predicted messages
    int flag = 1;
    for (int i = 0; i < 16; i++)
    {
        if (m[i] != *(pred_m + i))
        {
            printf("Preimage attack failed!");
            flag = 0;
            break;
        }
    }

    // print the messages only if the attack is sucessfull
    if (flag == 1)
    {
        printf("Preimage attack is successful! ");
        printf("The predicted messages are:\n");
        for (int i = 0; i < 16; i++)
        {
            printf("pred_m[%d] = %08x\n", i, *(pred_m + i));
        }
    }
    return 0;
}