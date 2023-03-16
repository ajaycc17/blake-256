// BLAKE-256 and BLAKE32 is used interchangably, both refer to the same hash function
#include "../blake_header.h"

// initialization of states
void initialize(state256 *S)
{
  S->h[0] = 0x6a09e667;
  S->h[1] = 0xbb67ae85;
  S->h[2] = 0x3c6ef372;
  S->h[3] = 0xa54ff53a;
  S->h[4] = 0x510e527f;
  S->h[5] = 0x9b05688c;
  S->h[6] = 0x1f83d9ab;
  S->h[7] = 0x5be0cd19;
  S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
  S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}

// round function
void round_function(state256 *S, const uint8_t *block)
{
  // states and message block - 32-bit each
  uint32_t v[16], m[16], i;

  // convert take 8-bit blocks into 32-bit and big-endian format
  for (i = 0; i < 16; ++i)
    m[i] = U8TO32_BIG(block + i * 4);

  // initial states
  for (i = 0; i < 8; ++i)
    v[i] = S->h[i];

  // rest states
  v[8] = S->s[0] ^ constant[0];
  v[9] = S->s[1] ^ constant[1];
  v[10] = S->s[2] ^ constant[2];
  v[11] = S->s[3] ^ constant[3];
  v[12] = constant[4];
  v[13] = constant[5];
  v[14] = constant[6];
  v[15] = constant[7];

  // XOR with t is not required when the block has padding-bits
  if (!S->nullt)
  {
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  // run the core function 14 times for blake-256 hash
  for (i = 0; i < 14; ++i)
  {
    // column step
    G(v, m, i, 0, 4, 8, 12, 0);
    G(v, m, i, 1, 5, 9, 13, 2);
    G(v, m, i, 2, 6, 10, 14, 4);
    G(v, m, i, 3, 7, 11, 15, 6);
    // diagonal step
    G(v, m, i, 0, 5, 10, 15, 8);
    G(v, m, i, 1, 6, 11, 12, 10);
    G(v, m, i, 2, 7, 8, 13, 12);
    G(v, m, i, 3, 4, 9, 14, 14);
  }

  // generating the hash with all updated states
  for (i = 0; i < 16; ++i)
    S->h[i % 8] ^= v[i];

  for (i = 0; i < 8; ++i)
    S->h[i] ^= S->s[i % 4];
}

// update the length of the block left and to fill
void pad_and_round(state256 *S, const uint8_t *in, uint64_t inlen)
{
  // space already filled
  int left = S->buflen;

  // space left in buffer
  int fill = 64 - left;

  // data left is not null and data to be left is greater than available space
  if (left && (inlen >= fill))
  {
    memcpy((void *)(S->buf + left), (void *)in, fill);
    S->t[0] += 512;

    if (S->t[0] == 0)
      S->t[1]++;

    round_function(S, S->buf);
    in += fill;
    inlen -= fill;
    left = 0;
  }

  // if message length is greater than or equal to 64
  while (inlen >= 64)
  {
    S->t[0] += 512;

    if (S->t[0] == 0)
      S->t[1]++;

    round_function(S, in);
    in += 64;
    inlen -= 64;
  }

  // if the message when block is empty
  if (inlen > 0)
  {
    memcpy((void *)(S->buf + left), (void *)in, (size_t)inlen);
    S->buflen = left + (int)inlen;
  }
  else
    S->buflen = 0;
}

// finalize blake 256
void final_block(state256 *S, uint8_t *out)
{
  uint8_t msglen[8], zo = 0x01, oo = 0x81;
  uint32_t lo = S->t[0] + (S->buflen << 3), hi = S->t[1];

  // space fill is less than greater than 2^32 bits
  if (lo < (S->buflen << 3))
    hi++;

  // get the length of message in 64-bit form
  U32TO8_BIG(msglen + 0, hi);
  U32TO8_BIG(msglen + 4, lo);

  // only one byte for padding is fill
  if (S->buflen == 55)
  {
    S->t[0] -= 8;
    pad_and_round(S, &oo, 1);
  }
  else
  {
    // atleast 2 bytes are available for padding
    if (S->buflen < 55)
    {
      // if buflen is 0
      if (!S->buflen)
        S->nullt = 1;

      S->t[0] -= 440 - (S->buflen << 3);
      pad_and_round(S, padding, 55 - S->buflen);
    }
    else
    {
      S->t[0] -= 512 - (S->buflen << 3);
      pad_and_round(S, padding, 64 - S->buflen);
      S->t[0] -= 440;
      pad_and_round(S, padding + 1, 55);
      S->nullt = 1;
    }

    // add one after padding 0 bits
    pad_and_round(S, &zo, 1);
    S->t[0] -= 8;
  }

  S->t[0] -= 64;
  pad_and_round(S, msglen, 8);

  // converting the 32-bit blocks into 8-bit hash output in big-endian
  U32TO8_BIG(out + 0, S->h[0]);
  U32TO8_BIG(out + 4, S->h[1]);
  U32TO8_BIG(out + 8, S->h[2]);
  U32TO8_BIG(out + 12, S->h[3]);
  U32TO8_BIG(out + 16, S->h[4]);
  U32TO8_BIG(out + 20, S->h[5]);
  U32TO8_BIG(out + 24, S->h[6]);
  U32TO8_BIG(out + 28, S->h[7]);
}

void blake32(uint8_t *out, const uint8_t *in, uint64_t inlen)
{
  state256 S;
  initialize(&S);
  pad_and_round(&S, in, inlen);
  final_block(&S, out);
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    // take the message
    char *in = "ajay1137";

    // length of message
    size_t msg_len = strlen(in);

    // output array - this will contain the final hash
    uint8_t out[32];

    // invoke the hashing function
    blake32(out, in, msg_len);

    // print the hash in hexadecimal form
    printf("BLAKE256 HASH for \"%s\" is: ", in);
    for (int i = 0; i < 32; ++i)
    {
      printf("%02x", out[i]);
    }
  }
  // if file input is not provided in CLI
  else
  {
    FILE *fp;
    int i, j, bytesread;
    uint8_t in[toRead], out[32];
    state256 S;

    // read until all the files are processed
    for (i = 1; i < argc; ++i)
    {
      fp = fopen(*(argv + i), "r");
      if (fp == NULL)
      {
        printf("Warning: No file named %s\n", *(argv + i));
        // take the message
        char *in = *(argv + i);

        // length of message
        size_t msg_len = strlen(in);

        // output array - this will contain the final hash
        uint8_t out[32];

        // invoke the hashing function
        blake32(out, in, msg_len);

        // print the hash in hexadecimal form
        printf("BLAKE256 HASH for \"%s\" is: ", in);
        for (int i = 0; i < 32; ++i)
        {
          printf("%02x", out[i]);
        }
        return 1;
      }

      // initialize a state with constants
      initialize(&S);

      // read the file given as input
      while (1)
      {
        // read in 64-bit blocks
        bytesread = fread(in, 1, toRead, fp);

        // if somethings is read update it else break
        if (bytesread)
          pad_and_round(&S, in, bytesread);
        else
          break;
      }

      // generate the hash digest
      final_block(&S, out);

      // print the hash digest
      printf("BLAKE-256 HASH for \"%s\" is: ", *(argv + i));
      for (j = 0; j < 32; ++j)
      {
        printf("%02x", out[j]);
      }

      // close the file pointer
      fclose(fp);
    }
  }
  return 0;
}