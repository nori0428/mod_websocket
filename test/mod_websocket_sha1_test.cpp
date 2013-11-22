#include <gtest/gtest.h>

#include <iostream>

#include "mod_websocket_sha1.h"

#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
#define TEST4   TEST4a TEST4b

class Sha1Test : public testing::Test {
protected:
  Sha1Test() {}
  ~Sha1Test() {}
  virtual void SetUp() {}
  virtual void TearDown() {}
};

TEST_F(Sha1Test, all) {
  std::string testarray[4] = {
    TEST1,
    TEST2,
    TEST3,
    TEST4
  };
  long int repeatcount[4] = { 1, 1, 1000000, 10 };
  std::string expectedstr[4] = {
    "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
    "84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
    "34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
    "DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52"
  };
  char expected[4][20] = {
    {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
     0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D},
    {0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
     0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1},
    {0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
     0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F},
    {0xDE, 0xA3, 0x56, 0xA2, 0xCD, 0xDD, 0x90, 0xC7, 0xA7, 0xEC,
     0xED, 0xC5, 0xEB, 0xB5, 0x63, 0x93, 0x4F, 0x46, 0x04, 0x52}
  };
  SHA_CTX sha;
  int i, j;
  sha1_byte md[20];

  for(j = 0; j < 4; ++j) {
    std::cout << "check: " << testarray[j] << std::endl;
    SHA1_Init(&sha);
    for(i = 0; i < repeatcount[j]; ++i) {
      SHA1_Update(&sha, (sha1_byte *)testarray[j].c_str(), testarray[j].size());
    }
    SHA1_Final(md, &sha);
    std::cout << "Message Digest:\n\t";
    for(i = 0; i < 20 ; ++i) {
      printf("%02X ", md[i]);
    }
    std::cout << "\n";
    std::cout << "Should match:\n\t" << expectedstr[j] << std::endl << std::endl;
    ASSERT_EQ(memcmp(md, expected[j], sizeof(md)), 0);
  }
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
