#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/fips_test.h>

int main(void)
{
    wc_SetSeed_Cb(wc_GenerateSeed);
    return wc_RunAllCast_fips();
}
