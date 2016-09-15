// Demonstrates miniz.c's compress() and uncompress() functions (same as zlib's).
// Public domain, May 15 2011, Rich Geldreich, richgel99@gmail.com. See "unlicense" statement at the end of tinfl.c.
// Chim remod for inflate without adler
#include "miniz.c"

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint;

int main(int argc, char *argv[])
{
  int cmp_status;
  uint8 *pCmp, *pUncomp;

  printf("miniz.c version: %s\n", MZ_VERSION);
  printf("Mod by Chim without adler32 check\n");

  if (argc!=3)
  {
    printf("[!] Usage: ./inflate_non_alder input output\n");
    return EXIT_SUCCESS;
  }

  FILE *f_inp = fopen(argv[1], "rb");
  if (!f_inp)
  {
    printf("[-] Error while open input file\n");
    return EXIT_FAILURE;
  }

  fseek(f_inp, 0L, SEEK_END);
  uLong cmp_len = ftell(f_inp);
  pCmp = (mz_uint8 *)malloc((size_t)cmp_len);
  if (!pCmp)
  {
    printf("[-] Out of memory!\n");
    return EXIT_FAILURE;
  }
  printf("[+] Compressed size = %ld\n", cmp_len);

  fseek(f_inp, 0L, SEEK_SET);
  fread(pCmp, 1, cmp_len, f_inp);
  fclose(f_inp);

  uLong uncomp_len = cmp_len*20;
  pUncomp = (mz_uint8 *)malloc((size_t)uncomp_len);
  if (!pUncomp)
  {
    printf("[-] Out of memory!\n");
    return EXIT_FAILURE;
  }

  //Decompress
  cmp_status = uncompress(pUncomp, &uncomp_len, pCmp, cmp_len);
    
  if (cmp_status != Z_OK)
  {
    printf("[-] Decompression failed!\n");
    free(pCmp);
    free(pUncomp);
    return EXIT_FAILURE;
  }

  printf("[+] Decompressed size = %ld\n", uncomp_len);

  FILE *f_out = fopen(argv[2], "wb");
  if (!f_inp)
  {
    printf("[-] Error while open output file\n");
    return EXIT_FAILURE;
  }

  fwrite(pUncomp, 1, uncomp_len, f_out);
  fclose(f_out);

  free(pCmp);
  free(pUncomp);

  printf("[+] Success!\n");

  return EXIT_SUCCESS;
}
