#include "Platform.h"
#include "Hashes.h"
#include "KeysetTest.h"
#include "SpeedTest.h"
#include "AvalancheTest.h"
#include "DifferentialTest.h"
#include "PMurHash.h"

#include <stdio.h>
#include <time.h>

#include <string.h>
#include <iostream>
#include "MurmurHash3.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdlib.h>

#include <string>
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;

struct HashInfo
{
  pfHash hash;
  int hashbits;
  uint32_t verification;
  const char * name;
  const char * desc;
};

HashInfo g_hashes[] =
{
  // first the bad hash funcs, failing tests:
  { DoNothingHash,        32, 0x00000000, "donothing32", "Do-Nothing function (only valid for measuring call overhead)" },
  { DoNothingHash,        64, 0x00000000, "donothing64", "Do-Nothing function (only valid for measuring call overhead)" },
  { DoNothingHash,       128, 0x00000000, "donothing128", "Do-Nothing function (only valid for measuring call overhead)" },
  { NoopOAATReadHash,     64, 0x00000000, "NOP_OAAT_read64", "Noop function (only valid for measuring call + OAAT reading overhead)" },

  { crc32,                32, 0x3719DB20, "crc32",       "CRC-32 soft" },

  { md5_32,               32, 0xC10C356B, "md5_32a",     "MD5, first 32 bits of result" },
  { sha1_32a,             32, 0xF9376EA7, "sha1_32a",    "SHA1, first 32 bits of result" },
#if 0
  { sha1_64a,             32, 0xF9376EA7, "sha1_64a",    "SHA1 64-bit, first 64 bits of result" },
  { sha2_32a,             32, 0xF9376EA7, "sha2_32a",    "SHA2, first 32 bits of result" },
  { sha2_64a,             64, 0xF9376EA7, "sha2_64a",    "SHA2, first 64 bits of result" },
  { BLAKE2_32a,           32, 0xF9376EA7, "blake2_32a",  "BLAKE2, first 32 bits of result" },
  { BLAKE2_64a,           64, 0xF9376EA7, "blake2_64a",  "BLAKE2, first 64 bits of result" },
  { bcrypt_64a,           64, 0xF9376EA7, "bcrypt_64a",  "bcrypt, first 64 bits of result" },
  { scrypt_64a,           64, 0xF9376EA7, "scrypt_64a",  "scrypt, first 64 bits of result" },
#endif

#ifdef __SSE2__
  { hasshe2_test,        256, 0xF5D39DFE, "hasshe2",     "SSE2 hasshe2, 256-bit" },
#endif
#if defined(__SSE4_2__) && defined(__x86_64__)
  { crc32c_hw_test,       32, 0x0C7346F0, "crc32_hw",    "SSE4.2 crc32 in HW" },
  { crc64c_hw_test,       64, 0xE7C3FD0E, "crc64_hw",    "SSE4.2 crc64 in HW" },
#if 0
  { crc32c_hw1_test,      32, 0x0C7346F0, "crc32_hw1",   "Faster Adler SSE4.2 crc32 in HW" },
#endif
#endif
// elf64 or macho64 only
//{ fhtw_test,            64, 0x0,        "fhtw",        "fhtw asm" },
  { FNV32a,               32, 0xE3CBBE91, "FNV1a",         "Fowler-Noll-Vo hash, 32-bit" },
  { FNV32a_YoshimitsuTRIAD,32,0xD8AFFD71, "FNV1a_YoshimitsuTRIAD", "FNV1a-YoshimitsuTRIAD 32-bit sanmayce" },
  { FNV64a,               64, 0x103455FC, "FNV64",       "Fowler-Noll-Vo hash, 64-bit" },
#if 0
  { fletcher2,            64, 0x0, "fletcher2",  "fletcher2 ZFS"} //TODO
  { fletcher4,            64, 0x0, "fletcher4",  "fletcher4 ZFS"} //TODO
  { Jesteress,            32, 0x0, "Jesteress",  "FNV1a-Jesteress 32-bit sanmayce" },
  { Meiyan,       	  32, 0x0, "Meiyan",     "FNV1a-Meiyan 32-bit sanmayce" },
#endif
  { Bernstein,            32, 0xBDB4B640, "bernstein",   "Bernstein, 32-bit" },
  { sdbm,                 32, 0x582AF769, "sdbm",        "sdbm as in perl5" },
  { x17_test,             32, 0x8128E14C, "x17",         "x17" },
  { JenkinsOOAT,          32, 0x83E133DA, "JenkinsOOAT", "Bob Jenkins' OOAT as in perl 5.18" },
  { JenkinsOOAT_perl,     32, 0xEE05869B, "JenkinsOOAT_perl", "Bob Jenkins' OOAT as in old perl5" },
  { lookup3_test,         32, 0x3D83917A, "lookup3",     "Bob Jenkins' lookup3" },
  { SuperFastHash,        32, 0x980ACD1D, "superfast",   "Paul Hsieh's SuperFastHash" },
  { MurmurOAAT_test,      32, 0x5363BD98, "MurmurOAAT",  "Murmur one-at-a-time" },
  { Crap8_test,           32, 0x743E97A1, "Crap8",       "Crap8" },
  { MurmurHash2_test,     32, 0x27864C1E, "Murmur2",     "MurmurHash2 for x86, 32-bit" },
  { MurmurHash2A_test,    32, 0x7FBD4396, "Murmur2A",    "MurmurHash2A for x86, 32-bit" },
#if defined(__x86_64__)
  { MurmurHash64A_test,   64, 0x1F0D3804, "Murmur2B",    "MurmurHash2 for x64, 64-bit" },
#endif
  { MurmurHash64B_test,   64, 0xDD537C05, "Murmur2C",    "MurmurHash2 for x86, 64-bit" },

  // and now the quality hash funcs, which mostly work
  { PMurHash32_test,      32, 0xB0F57EE3, "PMurHash32",  "Shane Day's portable-ized MurmurHash3 for x86, 32-bit." },
  { MurmurHash3_x86_32,   32, 0xB0F57EE3, "Murmur3A",    "MurmurHash3 for x86, 32-bit" },
  { MurmurHash3_x86_128, 128, 0xB3ECE62A, "Murmur3C",    "MurmurHash3 for x86, 128-bit" },
#if defined(__x86_64__)
  { MurmurHash3_x64_128, 128, 0x6384BA69, "Murmur3F",    "MurmurHash3 for x64, 128-bit" },
#endif
#if defined(__x86_64__)
  { fasthash32_test,      32, 0xE9481AFC, "fasthash32",        "fast-hash 32bit" },
  { fasthash64_test,      64, 0xA16231A7, "fasthash64",        "fast-hash 64bit" },
#endif
  { CityHash32_test,      32, 0x5C28AD62, "City32",      "Google CityHash32WithSeed (old)" },
  { CityHash64_test,      64, 0x25A20825, "City64",      "Google CityHash64WithSeed (old)" },
#if defined(__SSE4_2__) && defined(__x86_64__)
  { CityHash128_test,    128, 0x6531F54E, "City128",     "Google CityHash128WithSeed (old)" },
  { CityHashCrc128_test, 128, 0xD4389C97, "CityCrc128",  "Google CityHashCrc128WithSeed SSE4.2 (old)" },
#endif
#if defined(__x86_64__)
  { FarmHash32_test,      32, 0xA2E45238, "FarmHash32",  "Google FarmHash32WithSeed" },
  { FarmHash64_test,      64, 0x35F84A93, "FarmHash64",  "Google FarmHash64WithSeed" },
  { FarmHash128_test,    128, 0x9E636AAE, "FarmHash128", "Google FarmHash128WithSeed" },
  { farmhash32_c_test,    32, 0xA2E45238, "farmhash32_c",  "farmhash32_with_seed (C99)" },
  { farmhash64_c_test,    64, 0x35F84A93, "farmhash64_c",  "farmhash64_with_seed (C99)" },
  { farmhash128_c_test,  128, 0x9E636AAE, "farmhash128_c", "farmhash128_with_seed (C99)" },
#endif
  { siphash_test,         64, 0xC58D7F9C, "SipHash",     "SipHash - SSSE3 optimized" },
  { SpookyHash32_test,    32, 0x3F798BBB, "Spooky32",    "Bob Jenkins' SpookyHash, 32-bit result" },
  { SpookyHash64_test,    64, 0xA7F955F1, "Spooky64",    "Bob Jenkins' SpookyHash, 64-bit result" },
  { SpookyHash128_test,  128, 0x8D263080, "Spooky128",   "Bob Jenkins' SpookyHash, 128-bit result" },
#if defined(__x86_64__)
  { xxHash32_test,        32, 0xBA88B743, "xxHash32",    "xxHash, 32-bit for x64" },
  { xxHash64_test,        64, 0x024B7CF4, "xxHash64",    "xxHash, 64-bit" },
#if 0
  { xxhash256_test,       64, 0x024B7CF4, "xxhash256",   "xxhash256, 64-bit unportable" },
#endif
#endif  
  #if defined(__x86_64__)
  { metrohash64_1_test,       64, 0xEE88F7D2, "metrohash64_1",     "MetroHash64_1 for 64-bit" },
  { metrohash64_2_test,       64, 0xE1FC7C6E, "metrohash64_2",     "MetroHash64_2 for 64-bit" },
  { metrohash128_1_test,     128, 0x20E8A1D7, "metrohash128_1",    "MetroHash128_1 for 64-bit" },
  { metrohash128_2_test,     128, 0x5437C684, "metrohash128_2",    "MetroHash128_2 for 64-bit" },
#if defined(__SSE4_2__) && defined(__x86_64__)
  { metrohash64crc_1_test,    64, 0x29C68A50, "metrohash64crc_1",  "MetroHash64crc_1 for x64" },
  { metrohash64crc_2_test,    64, 0x2C00BD9F, "metrohash64crc_2",  "MetroHash64crc_2 for x64" },
  { metrohash128crc_1_test,  128, 0x5E75144E, "metrohash128crc_1", "MetroHash128crc_1 for x64" },
  { metrohash128crc_2_test,  128, 0x1ACF3E77, "metrohash128crc_2", "MetroHash128crc_2 for x64" },
#endif
#endif
#if defined(__x86_64__)
  { cmetrohash64_1_optshort_test, 64, 0xEE88F7D2, "cmetrohash64_1_optshort", "cmetrohash64_1 (shorter key optimized) , 64-bit for x64" },
  { cmetrohash64_1_test,        64, 0xEE88F7D2, "cmetrohash64_1",    "cmetrohash64_1, 64-bit for x64" },
  { cmetrohash64_2_test,        64, 0xE1FC7C6E, "cmetrohash64_2",    "cmetrohash64_2, 64-bit for x64" },
#endif
#if defined(__SSE4_2__) && defined(__x86_64__)
  { falkhash_test_cxx,          64, 0x2F99B071, "falkhash",          "falkhash.asm with aesenc, 64-bit for x64" },
#endif
};

HashInfo * findHash ( const char * name )
{
  for(size_t i = 0; i < sizeof(g_hashes) / sizeof(HashInfo); i++)
  {
    if(_stricmp(name,g_hashes[i].name) == 0) return &g_hashes[i];
  }

  return NULL;
}

//-----------------------------------------------------------------------------
// some common global variables for this test routine
static int maxHashLen = 128;

int printDrillBin(char * printbuf, char * buf, int len)
{
    for(int i=0; i< len; ++i){
        sprintf(printbuf+i*5, "\\\\x%02x", (unsigned char)buf[i]);
    }
    return len*4;
}

//generate hashes for different length of random buffers
void GenHashResults(HashInfo * hash64Info, HashInfo * hash32Info, vector<string>& resultVector)
{
    int totalNum = 800;
    int maxBufLen = 1024;
    int hashLen = hash64Info->hashbits / 8;
    int hash32bytes = hash32Info->hashbits / 8;
    int hash64bytes = hashLen;
    
    int beginChunkLen = 4;
    int chunkLen = 4;
    //each batch has identical chunkLen(4,8,16,32,64,128,256) except the last batch(4-->104)
    int maxBatch = 8;

    char * src = new char[100];
    strcpy(src, "abcdefghij");
    char * result64 = new char[maxHashLen];
    char * result32 = new char[maxHashLen];

    char * buf = new char[maxBufLen];
    int bufpointer = 0;

    char * printbuf = new char[16*1024];
    char * binbuf = new char[maxBufLen];

    resultVector.reserve(totalNum);

    memset(buf, 0, maxBufLen);

    hash64Info->hash(src, strlen(src), 0, result64);

    memcpy(buf, result64, hashLen);
    hash64Info->hash(buf, hashLen, *(unsigned int*)src, result64);
    
    int count = 0;
    unsigned int seed = 1684234849;
    chunkLen = beginChunkLen;
    for(int batchCount=0; batchCount < maxBatch - 1; ++batchCount) {

        if (chunkLen > maxBufLen)
            break;
        for(int i=count; i<count+totalNum/maxBatch; ++i){

            char * startp = buf + ((i*chunkLen) % (maxBufLen - chunkLen));
            printDrillBin(binbuf, startp, chunkLen);
            seed = i%2 ==0? 0 : 1684234849;
            hash64Info->hash(startp, chunkLen, seed, result64);
            hash32Info->hash(startp, chunkLen, seed, result32);

            if(batchCount == 0)
                memcpy(startp+hashLen, result64, hashLen);
            else {
                for (int j=0; j<maxBufLen - hashLen; j+=hashLen){
                    for (int k=0; k<hashLen; ++k)
                         ((unsigned char*)buf)[j+k] ^= ((unsigned char*)result64)[k];
                }
            }
            sprintf(printbuf,
                   "{\"src\":\"%s\", \"seed\": \"%u\", \"hash64\":\"%li\", \"hash32\":\"%i\"}",
                    binbuf, seed,  *(long*)result64, *(int*)result32);
                    //*(long*)(result64+hash64bytes - sizeof(long)),
                    //*(int*)(result32+hash64bytes - sizeof(int)));
             resultVector.push_back(string(printbuf));
        }

        //chunkLen grow by ^2: 4, 8, 16, 32, 64, ,...
        chunkLen = beginChunkLen << batchCount;

        count += totalNum/maxBatch;
     }
     //last batch, chunkLen grows from HashLen+1 ==>HashLen+totalNum/maxBatch
     for (int i=count; i< totalNum; ++i){
         chunkLen = hashLen + (i - count) + 1;
         printDrillBin(binbuf, buf, chunkLen);
         seed = i%2 ==0? 0 : 1684234849;

         hash64Info->hash(buf, chunkLen, seed, result64);
         hash32Info->hash(buf, chunkLen, seed, result32);

         for (int j=0; j<maxBufLen - hashLen; j+=hashLen){
             for (int k=0; k<hashLen; ++k)
                ((unsigned char*)buf)[j+k] ^= ((unsigned char*)result64)[k];
         }
         sprintf(printbuf,
                "{\"src\":\"%s\", \"seed\": \"%u\", \"hash64\":\"%li\", \"hash32\":\"%i\"}",
                binbuf, seed,  *(long*)result64, *(int*)result32);

         resultVector.push_back(string(printbuf));
     }
}

void GenHashAsDoubleResult(HashInfo * hash64Info, HashInfo * hash32Info, vector<string>& resultVector) 
{
    int maxBufLen = 1024;

    double dnum = 1.0;
    int seed = 645766159;

    int totalNum = 800;

    char * result64 = new char[maxHashLen];
    char * result32 = new char[maxHashLen];

    char* printbuf = new char[16*1024];
    char * binbuf = new char[maxBufLen];

    int hashLen = hash64Info->hashbits / 8;
    int hash32bytes = hash32Info->hashbits / 8;
    int hash64bytes = hashLen;

    resultVector.reserve(totalNum);

    for (int i=0; i< totalNum; ++i) {
        printDrillBin(binbuf, (char*)&dnum, 8);
        seed = i%2 ==0? 0 : 645766159;

        //this function is for x64 where sizeof(double)=8
        hash64Info->hash(&dnum, 8, seed, result64);
        hash32Info->hash(&dnum, 8, seed, result32);

        sprintf(printbuf,
               "{\"src\":\"%16.16f\", \"srcbinary\":\"%s\", \"seed\": \"%u\", \"hash64\":\"%li\", \"hash32\":\"%i\"}",
               dnum, binbuf, seed,  *(long*)result64, *(int*)result32);

        resultVector.push_back(string(printbuf));

        dnum = (double) (((long*)result64)[0]  & 0x7fffffff)  / 1.417;
    }

}

void saveResult(const string& fileName, const vector<string>& results)
{
    ofstream ofile;
    ofile.open(fileName.c_str());
    for (int i=0; i<results.size(); ++i){
      ofile << results[i] << std::endl;
    }
    ofile.close();
}

//Take at most two hashes
void getHashInfos(const string& namestr, HashInfo ** hashes){
  int pos = namestr.find(',');
  HashInfo * hash32Info, * hash64Info;
  string name64, name32;
  if(pos >= 0){
    name64 = namestr.substr(0, pos);
    name32 = namestr.substr(pos+1);
  }
  else {
    name64 = namestr;
    name32 = namestr;
  }
  hash32Info = findHash(name32.c_str());
  hash64Info = findHash(name64.c_str());
  hashes[0] = hash64Info;
  hashes[1] = hash32Info;
  return;

}
//-----------------------------------------------------------------------------

void testHash ( const string& namestr, const char * filePrefix )
{
  HashInfo * hashes[2];
  getHashInfos(namestr, hashes);

  if(hashes[0]== NULL || hashes[1] == NULL)
  {
    printf("Invalid hash '%s' specified\n", namestr.c_str());
    return;
  }

  vector<string> hashResultStrs;
  
  string actualPrefix;
  if(filePrefix == NULL)
    actualPrefix = hashes[0]->name;
  else
    actualPrefix = filePrefix;

  GenHashAsDoubleResult(hashes[0], hashes[1], hashResultStrs);
  saveResult(actualPrefix + string("_double.json"), hashResultStrs);
  hashResultStrs.clear();
  GenHashResults(hashes[0], hashes[1], hashResultStrs);
  saveResult(actualPrefix + string("_buf.json"), hashResultStrs);
}

unsigned char getHalfByte(unsigned char b) {
  if (b>='0' && b<='9')
     return b - '0';
  else if (b>='a' && b<='f') 
     return b - 'a' + 10;
  else if (b>='A' && b<='F')
     return b - 'A' + 10;
  return 0xff;
}

int hashInput(const string& namestr, const string& toBeHashed, const char * hashSeed)
{
  HashInfo * hashes[2];
  getHashInfos(namestr, hashes);
  
  if(hashes[0] == NULL || hashes[1] == NULL)
  {
    printf("Invalid hash '%s' specified\n", namestr.c_str());
    return -1;
  }

  int seed = 0;
  if (hashSeed != NULL) {
    seed = atoi(hashSeed);
  }
  char result0[maxHashLen];
  char result1[maxHashLen];
  unsigned char inBuf[1024];
  int bufCount=0;

  if(toBeHashed[0]=='0' && (toBeHashed[1]=='x' || toBeHashed[1]=='X')){
    //take hex input(start with '0x') as binary buffer.
    int inLen=0;
    int inTextLen = toBeHashed.size();
    int pos = 2;
    while(pos<inTextLen) {
       if(toBeHashed[pos]=='\\') 
         pos++;
       else {
         unsigned char v1 = getHalfByte(toBeHashed[pos]);
         unsigned char v2 = getHalfByte(toBeHashed[pos+1]);
         if (v1==0xff || v2==0xff){
           printf("Invalidate binary hex string: %s", toBeHashed.c_str());
           return -2;
         }
         inBuf[bufCount] = (v1 & 0x0f)<<4 | (v2 & 0x0f);
         bufCount++;
         pos+=2;
       }
    }
    hashes[0]->hash(inBuf, bufCount, seed, result0);
    hashes[1]->hash(inBuf, bufCount, seed, result1);
  }
  else {// input is a regular long (8 bytes)
    unsigned long inNum = atol(toBeHashed.c_str());

    hashes[0]->hash(&inNum, sizeof(long), seed, result0);
    hashes[1]->hash(&inNum, sizeof(long), seed, result1);
  }
  printf("hash64=%li, hash32=%i\n", *(long*)result0, *(int*)result1);
}

int main ( int argc, char ** argv )
{
  const char * defaulthash = "murmur3f"; 
  const char * hashToTest = defaulthash;

  if(argc < 2) {
    printf("No test hash given on command line, testing %s.\n", hashToTest);
    printf("Usage: gethash <hash64>[,hash32](no space) --json=[output file name]\n");
    printf("       gethash <hash64>[,hash32](no space) --input=<long_integer|'string'>\n");
    printf("       e.g. 'gethash Murmur3F', 'gethash Murmur3F,Murmur3A'\n");
    printf("       'gethash Murmur3F --input=899123213'\n");
    printf("       'gethash Murmur3F --input=899123213 --seed=1684234849\n");
    printf("       if hash32 is not given, the same hash64 will be used\n");

    return 0;
  }
  hashToTest = argv[1];
  char * filePrefix = NULL;

  if (argc > 2){
    char * toBeHashed = NULL;
    char * hashSeed = NULL;

    int count = 2;
    while (count < argc) {
      char * curArg = argv[count];
      if (strncmp("--input=", curArg, 8)==0){
        toBeHashed = curArg+8;
      }
      else if (strncmp("--seed=", curArg, 7)==0) {
        hashSeed = curArg+7;
      }
      else if (strncmp("--json=", curArg, 7)==0) {
        filePrefix = curArg+7;
      }
      count++;
    }
    if(filePrefix != NULL) {
      testHash(hashToTest, filePrefix);
      return 0;
    }
    else if (toBeHashed == NULL ) {
      printf("No input to hash!\n");
      exit(0);
    }
    if (toBeHashed != NULL){
      hashInput(hashToTest, toBeHashed, hashSeed);
    }
  }

  return 0;
}
