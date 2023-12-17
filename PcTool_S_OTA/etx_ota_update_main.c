
/**************************************************

file: etx_ota_update_main.c
purpose: 

compile with the command: gcc etx_ota_update_main.c RS232\rs232.c -IRS232 -Wall -Wextra -o2 -o etx_ota_app

**************************************************/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include "rs232.h"
#include "sha1.h"

#define ETX_OTA_MAX_BLOCK_SIZE ( 1024 )
#define ETX_OTA_MAX_FW_SIZE    ( ETX_OTA_MAX_BLOCK_SIZE * 48 )

uint8_t APP_BIN[ETX_OTA_MAX_FW_SIZE];
uint32_t appcrc ;
uint8_t shaoutput[20];
uint64_t secf;


void delay(uint32_t us)
{
#ifdef _WIN32
    //Sleep(ms);
    __int64 time1 = 0, time2 = 0, freq = 0;

    QueryPerformanceCounter((LARGE_INTEGER *) &time1);
    QueryPerformanceFrequency((LARGE_INTEGER *)&freq);

    do {
        QueryPerformanceCounter((LARGE_INTEGER *) &time2);
    } while((time2-time1) < us);
#else
    usleep(us);
#endif
}


static void calculate_sha1(const uint8_t* msg, unsigned nbytes, uint8_t* output)
{
  struct sha1 ctx;

  sha1_reset(&ctx);
  sha1_input(&ctx, msg, nbytes);
  sha1_result(&ctx, output);
}

uint64_t mod_exp(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }

    return result;
}

// Function to calculate the greatest common divisor (GCD) of two numbers
uint64_t gcd(uint64_t a, uint64_t b) {
    if (b == 0) {
        return a;
    }
    return gcd(b, a % b);
}

// Function to calculate the modular multiplicative inverse (a^(-1) mod m)
uint64_t mod_inverse(uint64_t a, uint64_t m) {
    for (uint64_t x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return 0; // Inverse does not exist
}

// Function to generate RSA key pair
void generate_rsa_key_pair(uint64_t *public_key, uint64_t *private_key, uint64_t *modulus) {
    // Choose two large prime numbers (for simplicity, these are hardcoded here)
    uint64_t p = 23;
    uint64_t q = 29;

    *modulus = p * q;
    uint64_t phi = (p - 1) * (q - 1);

    // Choose public exponent (for simplicity, this is hardcoded here)
    *public_key = 17;

    // Calculate private exponent
    *private_key = mod_inverse(*public_key, phi);
}

// Function to encrypt a message using RSA
void rsa_encrypt(uint8_t *plaintext, size_t len, uint64_t public_key, uint64_t modulus, uint64_t *ciphertext) {
    for (size_t i = 0; i < len; i++) {
        ciphertext[i] = mod_exp(plaintext[i], public_key, modulus);
    }
}

// Function to decrypt a message using RSA
void rsa_decrypt(uint64_t *ciphertext, size_t len, uint64_t private_key, uint64_t modulus, uint8_t *plaintext) {
    for (size_t i = 0; i < len; i++) {
        plaintext[i] = mod_exp(ciphertext[i], private_key, modulus);
    }
}


void uint64_to_uint8(uint64_t *input, size_t len, uint8_t *output) {
    for (size_t i = 0; i < len; ++i) {
        for (size_t j = 0; j < sizeof(uint64_t); ++j) {
            output[i * sizeof(uint64_t) + j] = (uint8_t)((input[i] >> (8 * j)) & 0xFF);
        }
    }
}

void uint8_to_uint64(uint8_t *input, size_t len, uint64_t *output) {
    for (size_t i = 0; i < len; i += sizeof(uint64_t)) {
        uint64_t value = 0;
        for (size_t j = 0; j < sizeof(uint64_t) && i + j < len; ++j) {
            value |= (uint64_t)input[i + j] << (8 * j);
        }
        output[i / sizeof(uint64_t)] = value;
    }
}

int main(int argc, char *argv[])
{
  char bin_name[1024];
  int ex = 0;
  FILE *Fptr = NULL;
    uint64_t public_key, private_key, modulus;
    size_t len = 20;

    uint8_t bytes[160];
    generate_rsa_key_pair(&public_key, &private_key, &modulus);

  do
  {
    if( argc <= 2 )
    {
      printf("Please feed the COM PORT number and the Application Image....!!!\n");
      printf("Example: .\\etx_ota_app.exe 8 ..\\..\\Application\\Debug\\Blinky.bin");
      ex = -1;
      break;
    }

    //get the COM port Number
    strcpy(bin_name, argv[2]);

    printf("Opening Binary file : %s\n", bin_name);

    Fptr = fopen(bin_name,"rb");

    if( Fptr == NULL )
    {
      printf("Can not open %s\n", bin_name);
      ex = -1;
      break;
    }

    fseek(Fptr, 0L, SEEK_END);
    uint32_t app_size = ftell(Fptr);
    fseek(Fptr, 0L, SEEK_SET);

    printf("File size = %d\n", app_size);

    if( app_size > ETX_OTA_MAX_FW_SIZE )
    {
      printf("Application Size is more than the Maximum Size (%dKb)\n", ETX_OTA_MAX_FW_SIZE/ETX_OTA_MAX_BLOCK_SIZE);
      ex = -1;
      break;
    }

    //read the full image
    if( fread( APP_BIN, 1, app_size, Fptr ) != app_size )
    {
      printf("App/FW read Error\n");
      ex = -1;
      break;
    
    }
    printf("%d...\n",app_size);
    calculate_sha1(APP_BIN, app_size , shaoutput);
    printf("HASH VALUE IS \n"); 
    for(int i =0 ; i<20 ; i++){
    printf(" %X",shaoutput[i]); 
     }
    printf("\n");
    uint64_t SIGNATURE[len];
    rsa_encrypt(shaoutput, len, private_key, modulus, SIGNATURE);
     printf("SIGNATURE: ");
    for (size_t i = 0; i < len; i++) {
        printf("%llu ", SIGNATURE[i]);
    }
    printf("\n");
   uint64_to_uint8(SIGNATURE , len , bytes);
    printf("Converted uint8_t array: ");
      for (size_t i = 0; i < 160 ; i++) {
          printf("%02X ", bytes[i]);
      }

    printf("\n");
      uint8_to_uint64(bytes, len, SIGNATURE);
      printf("CONVERTED UINT64_T ARRAY: ");
      for (size_t i = 0; i < len; i++) {
          printf("%llu ", SIGNATURE[i]);
      }
      printf("\n");



    // Hexadecimal message (0xFA, 0xAA)
    size_t len = 20;

      printf("\n");

 

    uint8_t decrypted_SIGNATURE[len];
    rsa_decrypt(SIGNATURE, len, public_key, modulus, decrypted_SIGNATURE);

    printf("DECRYPTED SIGNATURE  : ");
    for (size_t i = 0; i < len; i++) {
        printf("%X ", decrypted_SIGNATURE[i]);
    }
    printf("\n");
printf("%d and  %d and %d" , public_key , private_key , modulus) ; 


    if( ex < 0 )
    {
      break;
    }

  } while (false);

  if(Fptr)
  {
    fclose(Fptr);
  }

  if( ex < 0 )
  {
    printf("OTA ERROR\n");
  }
  return(ex);
}

