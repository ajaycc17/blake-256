// Invert a G function and preimage attack on 1.5 round of BLAKE32
#include <bits/stdc++.h>
using namespace std;

// 8-bit blocks to a 32-bit block
#define U8TO32_BIG(p)                                          \
    (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) | \
     ((uint32_t)((p)[2]) << 8) | ((uint32_t)((p)[3])))

// 32-bit block to 8-bit blocks
#define U32TO8_BIG(p, v)           \
    (p)[0] = (uint8_t)((v) >> 24); \
    (p)[1] = (uint8_t)((v) >> 16); \
    (p)[2] = (uint8_t)((v) >> 8);  \
    (p)[3] = (uint8_t)((v));

// right circular shift
#define ROT(x, n) (((x) << (32 - n)) | ((x) >> (n)))
// left circular shift
#define ROTL(x, n) (((x) >> (32 - n)) | ((x) << (n)))

// permutation table
const uint8_t sigma[][16] =
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}};

// constants
const uint32_t constant[16] =
    {
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917};

// core function
void G(uint32_t v[], uint32_t m[], uint32_t r, int a, int b, int c, int d, int e)
{
    v[a] += m[sigma[r][e]] + v[b];
    v[d] = ROT(v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b] = ROT(v[b] ^ v[c], 12);
    v[a] += m[sigma[r][e + 1]] + v[b];
    v[d] = ROT(v[d] ^ v[a], 8);
    v[c] += v[d];
    v[b] = ROT(v[b] ^ v[c], 7);
}

// round function
void round_function()
{
    // hash for 2round
    string hash = "a3841e5364a0ea7c88be3497415b540b00098246c120e3e2dfa66cccfd9b6e29";
    // 32-bit messages
    uint32_t m[16] = {0x8a4b91c2, 0x8a9231c2, 0x6b9291c2, 0x8a929032, 0x8a1251c2, 0x8a9291d7, 0x8a9291c4, 0x8a9291c1, 0x8a929156, 0x8a9291c3, 0x8a9291c5, 0x129291c2, 0x339291c2, 0x809291c2, 0x849291c2, 0x8c2241c2};

    // initial states before any round
    uint32_t v0[16] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, constant[0], constant[1], constant[2], constant[3], constant[4], constant[5], constant[6], constant[7]};

    // initialising another variable for state after 0.5 round
    uint32_t v_05[16] = {0}, v_1[16] = {0}, v_15[16] = {0};
    uint32_t state_05[16] = {0}, state_1[16] = {0}, mess[16] = {0};
    for (int i = 0; i < 16; i++)
        v_15[i] = v0[i];

    uint32_t r = 0;
    // round 0.5
    G(v_15, m, r, 0, 4, 8, 12, 0);
    G(v_15, m, r, 1, 5, 9, 13, 2);
    G(v_15, m, r, 2, 6, 10, 14, 4);
    G(v_15, m, r, 3, 7, 11, 15, 6);

    // get new states after 0.5 round
    for (int i = 0; i < 16; i++)
        v_05[i] = v_15[i];

    // round 1
    G(v_15, m, r, 0, 5, 10, 15, 8);
    G(v_15, m, r, 1, 6, 11, 12, 10);
    G(v_15, m, r, 2, 7, 8, 13, 12);
    G(v_15, m, r, 3, 4, 9, 14, 14);

    // get new states after 1 round
    for (int i = 0; i < 16; i++)
        v_1[i] = v_15[i];

    // round 1.5
    r = 1;
    G(v_15, m, r, 0, 4, 8, 12, 0);
    G(v_15, m, r, 1, 5, 9, 13, 2);
    G(v_15, m, r, 2, 6, 10, 14, 4);
    G(v_15, m, r, 3, 7, 11, 15, 6);

    // print all the states
    cout << "Initial \t Round0.5 \t Round1 \t Round1.5\n";
    for (int i = 0; i < 16; i++)
    {
        printf("%02x \t %02x \t %02x \t %02x\n", v0[i], v_05[i], v_1[i], v_15[i]);
    }

    // Preimage attack
    // guess m8, m10, m11, and v10(after 0.5 round) - 2^128 guess at max
    uint32_t m8 = m[8], m10 = m[10], m11 = m[11], v10 = 0xc2ccfa29;

    // using 4th eqn. determine (v4-v7) after 1 round
    state_1[4] = ROTL(ROTL(v_15[4], 7) ^ v_15[8], 12) ^ (v_15[8] - v_15[12]);
    state_1[5] = ROTL(ROTL(v_15[5], 7) ^ v_15[9], 12) ^ (v_15[9] - v_15[13]);
    state_1[6] = ROTL(ROTL(v_15[6], 7) ^ v_15[10], 12) ^ (v_15[10] - v_15[14]);
    state_1[7] = ROTL(ROTL(v_15[7], 7) ^ v_15[11], 12) ^ (v_15[11] - v_15[15]);

    // using 5th eqn. determine (v8-v11) (after 1 round)
    state_1[8] = v_15[8] - v_15[12] - (ROTL(v_15[12], 8) ^ v_15[0]);
    state_1[9] = v_15[9] - v_15[13] - (ROTL(v_15[13], 8) ^ v_15[1]);
    state_1[10] = v_15[10] - v_15[14] - (ROTL(v_15[14], 8) ^ v_15[2]);
    state_1[11] = v_15[11] - v_15[15] - (ROTL(v_15[15], 8) ^ v_15[3]);

    // print calculated values
    cout << "\nAfter 1.5 round, the states v_1\n";
    for (int i = 4; i <= 7; i++)
    {
        printf("v_1[%d] = %02x\n", i, state_1[i]);
    }
    for (int i = 8; i <= 11; i++)
    {
        printf("v_1[%d] = %02x\n", i, state_1[i]);
    }

    // using 7th eqn. v12 and v13 (after 1 round)
    state_1[12] = ROTL((ROTL(v_15[12], 8) ^ v_15[0]), 16) ^ (v_15[0] - (ROTL(v_15[4], 7) ^ v_15[8]) - m10);
    state_1[13] = ROTL((ROTL(v_15[13], 8) ^ v_15[1]), 16) ^ (v_15[1] - (ROTL(v_15[5], 7) ^ v_15[9]) - m8);
    for (int i = 12; i <= 13; i++)
    {
        printf("v_1[%d] = %02x\n", i, state_1[i]);
    }

    // Determine v6 and v7 after 0.5 round using 4th eqn
    state_05[6] = ROTL(ROTL(state_1[6], 7) ^ state_1[11], 12) ^ (state_1[11] - state_1[12]);
    state_05[7] = ROTL(ROTL(state_1[7], 7) ^ state_1[8], 12) ^ (state_1[8] - state_1[13]);
    printf("v_05[6] = %02x\n", state_05[6]);
    printf("v_05[7] = %02x\n", state_05[7]);

    // determine mess[4] using 2nd eqn
    // G(v_15, m, r, 2, 6, 10, 14, 4);
    mess[4] = (ROTL(((ROTL((ROTL(state_05[6], 7) ^ v10), 12) ^ v0[6]) - v0[10]), 16) ^ v0[14]) - v0[2] - v0[6];
    printf("mess[4] = %02x\n", mess[4]);

    // determine v1 after round 1 using 2nd eq.
    // G(v_15, m, r, 1, 5, 9, 13, 2);
    state_1[1] = (ROTL(((ROTL((ROTL(v_15[5], 7) ^ v_15[9]), 12) ^ state_1[5]) - state_1[9]), 16) ^ state_1[13]) - state_1[5] - mess[4];
    printf("v_1[1] = %02x\n", state_1[1]);

    // determine v_14 after 0.5 round using 6th eq
    state_05[14] = state_05[10] - v0[10] - ROTL((v0[14] ^ (v0[2] + v0[6] + mess[4])), 16);
    printf("v_05[14] = %02x\n", state_05[14]);

    // determine v_1 after 0.5 round using 3rd eqn
    state_05[1] = state_1[1] - (ROTL(state_1[6], 7) ^ state_1[11]) - m11 - state_05[6] - m10;
    printf("v_05[1] = %02x\n", state_05[1]);

    // determine v_11 after 0.5 round using 5th eqn
    state_05[11] = state_1[11] - state_1[12] - (ROTL(state_1[12], 8) ^ state_1[1]);
    printf("v_05[11] = %02x\n", state_05[11]);

    // determine v_12 after 0.5 round using 2nd eqn
    state_05[12] = ROTL(((ROTL((ROTL(state_1[6], 7) ^ state_1[11]), 12) ^ state_05[6]) - state_05[11]), 16) ^ (state_05[1] + state_05[6] + m10);
    printf("v_05[12] = %02x\n", state_05[12]);

    // determine v_2 after 0.5 round using 5th eqn
    state_05[2] = (state_05[10] - state_05[14] - v0[10]) ^ ROTL(state_05[14], 8);
    printf("v_05[2] = %02x\n", state_05[2]);

    // determine mess[5] using 8th eqn
    mess[5] = (ROTL(((ROTL((ROTL(state_05[6], 7) ^ state_05[10]), 12) ^ v0[6]) - v0[10]), 16) ^ v0[14]) + (ROTL(state_05[6], 7) ^ state_05[10]) - state_05[2];
    mess[5] = -mess[5];
    printf("mess[5] = %02x\n", mess[5]);

    // determine mess[6] using 2nd eqn
    mess[6] = (ROTL(((ROTL((ROTL(state_05[7], 7) ^ state_05[11]), 12) ^ v0[7]) - v0[11]), 16) ^ v0[15]) - v0[7] - v0[3];
    printf("mess[6] = %02x\n", mess[6]);

    // determine v15 after 1 round using 7th eqn
    state_1[15] = ROTL((ROTL(v_15[15], 8) ^ v_15[3]), 16) ^ (v_15[3] - (ROTL(v_15[7], 7) ^ v_15[11]) - mess[6]);
    printf("v_1[15] = %02x\n", state_1[15]);

    // determine v15 after 0.5 round using 6th eqn
    // G(v_15, m, r, 3, 7, 11, 15, 6);
    state_05[15] = state_05[11] - v0[11] - ROT((v0[15] ^ (v0[3] + v0[7] + mess[6])), 16);
    printf("v_05[15] = %02x\n", state_05[15]);

    // determine v5 after 0.5 round using 4th eqn
    state_05[5] = ROTL((ROTL(state_1[5], 7) ^ state_1[10]), 12) ^ (state_1[10] - state_1[15]);
    printf("v_05[5] = %02x\n", state_05[5]);

    // determine v0 after 1 round using 5th eqn
    // state_05[15] = c = c′ − d′ − ((d′ ≪ 8) ⊕ a′);
    // printf("v_05[15] = %02x\n", state_05[15]);
}

// main function
int main()
{
    round_function();
    return 0;
}