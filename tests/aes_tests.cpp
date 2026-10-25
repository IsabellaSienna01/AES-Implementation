#include "../include/crypto/aes.hpp"
#include <iostream>
#include <cassert>
#include <cctype>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

// Helper function to lowercase a hex string for case-insensitive comparison
std::string to_lower(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Helper to convert hex string to byte vector
std::vector<unsigned char> hex_to_bytes(const std::string &hex_str) {
    std::string raw = hex2text(hex_str);
    return std::vector<unsigned char>(raw.begin(), raw.end());
}

// Helper to convert byte vector to hex string
std::string bytes_to_hex(const std::vector<unsigned char> &bytes) {
    std::string raw(bytes.begin(), bytes.end());
    return to_lower(text2hex(raw));
}

void test_nist_aes128_known_answer_vectors() {
    std::cout << "[TEST] 1. NIST SP 800-38A F.1.1 (AES-128 Electronic Codebook Test Vectors)..." << std::endl;

    std::string key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    std::vector<unsigned char> key = hex_to_bytes(key_hex);
    AES aes(key);

    // Block 1
    std::string pt1_hex = "6bc1bee22e409f96e93d7e117393172a";
    std::string expected_ct1_hex = "3ad77bb40d7a3660a89ecaf32466ef97";
    std::vector<unsigned char> ct1 = aes.encrypt_block(hex_to_bytes(pt1_hex));
    assert(bytes_to_hex(ct1) == expected_ct1_hex);
    std::vector<unsigned char> decrypted1 = aes.decrypt_block(ct1);
    assert(bytes_to_hex(decrypted1) == pt1_hex);

    // Block 2
    std::string pt2_hex = "ae2d8a571e03ac9c9eb76fac45af8e51";
    std::string expected_ct2_hex = "f5d3d58503b9699de785895a96fdbaaf";
    std::vector<unsigned char> ct2 = aes.encrypt_block(hex_to_bytes(pt2_hex));
    assert(bytes_to_hex(ct2) == expected_ct2_hex);
    std::vector<unsigned char> decrypted2 = aes.decrypt_block(ct2);
    assert(bytes_to_hex(decrypted2) == pt2_hex);

    // Block 3
    std::string pt3_hex = "30c81c46a35ce411e5fbc1191a0a52ef";
    std::string expected_ct3_hex = "43b1cd7f598ece23881b00e3ed030688";
    std::vector<unsigned char> ct3 = aes.encrypt_block(hex_to_bytes(pt3_hex));
    assert(bytes_to_hex(ct3) == expected_ct3_hex);
    std::vector<unsigned char> decrypted3 = aes.decrypt_block(ct3);
    assert(bytes_to_hex(decrypted3) == pt3_hex);

    // Block 4
    std::string pt4_hex = "f69f2445df4f9b17ad2b417be66c3710";
    std::string expected_ct4_hex = "7b0c785e27e8ad3f8223207104725dd4";
    std::vector<unsigned char> ct4 = aes.encrypt_block(hex_to_bytes(pt4_hex));
    assert(bytes_to_hex(ct4) == expected_ct4_hex);
    std::vector<unsigned char> decrypted4 = aes.decrypt_block(ct4);
    assert(bytes_to_hex(decrypted4) == pt4_hex);

    std::cout << "       --> NIST SP 800-38A AES-128 PASSED! (4/4 blocks verified)" << std::endl;
}

void test_fips197_aes192_and_aes256_vectors() {
    std::cout << "[TEST] 2. FIPS 197 Appendix C (AES-192 & AES-256 Test Vectors)..." << std::endl;

    // FIPS 197 C.2 AES-192
    std::string key192_hex = "000102030405060708090a0b0c0d0e0f1011121314151617";
    std::string pt192_hex  = "00112233445566778899aabbccddeeff";
    std::string exp192_hex = "dda97ca4864cdfe06eaf70a0ec0d7191";

    AES aes192(hex_to_bytes(key192_hex));
    std::vector<unsigned char> ct192 = aes192.encrypt_block(hex_to_bytes(pt192_hex));
    assert(bytes_to_hex(ct192) == exp192_hex);
    assert(bytes_to_hex(aes192.decrypt_block(ct192)) == pt192_hex);
    std::cout << "       --> FIPS 197 AES-192 PASSED!" << std::endl;

    // FIPS 197 C.3 AES-256
    std::string key256_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    std::string pt256_hex  = "00112233445566778899aabbccddeeff";
    std::string exp256_hex = "8ea2b7ca516745bfeafc49904b496089";

    AES aes256(hex_to_bytes(key256_hex));
    std::vector<unsigned char> ct256 = aes256.encrypt_block(hex_to_bytes(pt256_hex));
    assert(bytes_to_hex(ct256) == exp256_hex);
    assert(bytes_to_hex(aes256.decrypt_block(ct256)) == pt256_hex);
    std::cout << "       --> FIPS 197 AES-256 PASSED!" << std::endl;
}

void test_cbc_mode_and_padding_lengths() {
    std::cout << "[TEST] 3. AES-128-CBC with PKCS#7 Padding on Variable Lengths..." << std::endl;

    std::string key = "16byteSecretKey!";
    std::string iv  = "16byteRandomIV!!";
    std::vector<unsigned char> key_bytes(key.begin(), key.end());
    std::vector<unsigned char> iv_bytes(iv.begin(), iv.end());

    AES aes(key_bytes);

    // Test messages with various sizes: 0, 1, 15, 16, 17, 31, 32, 100 bytes
    std::vector<int> test_lengths = {0, 1, 7, 15, 16, 17, 31, 32, 65, 128};

    for (int len : test_lengths) {
        std::string original_msg = "";
        for (int i = 0; i < len; i++) {
            original_msg += (char)('A' + (i % 26));
        }

        std::vector<unsigned char> pt(original_msg.begin(), original_msg.end());
        std::vector<unsigned char> ct = aes.encrypt_cbc(pt, iv_bytes);

        // Ciphertext size must always be a non-zero multiple of 16
        assert(ct.size() > 0);
        assert(ct.size() % 16 == 0);

        std::vector<unsigned char> decrypted = aes.decrypt_cbc(ct, iv_bytes);
        std::string recovered_msg(decrypted.begin(), decrypted.end());

        assert(recovered_msg == original_msg);
    }

    std::cout << "       --> CBC variable length round-trips PASSED! (0 to 128 bytes verified)" << std::endl;
}

void test_high_level_encrypt_and_decrypt() {
    std::cout << "[TEST] 4. High-Level encrypt() and decrypt() Wrappers..." << std::endl;

    std::string key = "SharedSecret1234";
    std::string secret_message = "KDC, Alice, and Bob are securely authenticated!";

    // Test with auto-generated IV (IV is prepended: IV || Ciphertext)
    std::string enc_hex = encrypt(secret_message, key);
    std::string dec = decrypt(enc_hex, key);
    assert(dec == secret_message);

    // Test with explicit IV passed to encrypt (IV is prepended: IV || Ciphertext)
    std::string explicit_iv = "InitialVector001";
    std::string enc_hex_iv = encrypt(secret_message, key, explicit_iv);
    std::string dec_iv = decrypt(enc_hex_iv, key);
    assert(dec_iv == secret_message);

    // Test decrypt when ciphertext does not have IV prepended, but IV is passed to decrypt
    std::vector<unsigned char> pt_raw(secret_message.begin(), secret_message.end());
    std::vector<unsigned char> iv_raw(explicit_iv.begin(), explicit_iv.end());
    AES aes_cbc(key);
    std::vector<unsigned char> pure_ct = aes_cbc.encrypt_cbc(pt_raw, iv_raw);
    std::string pure_ct_hex = bytes_to_hex(pure_ct);

    std::string dec_pure = decrypt(pure_ct_hex, key, explicit_iv);
    assert(dec_pure == secret_message);

    std::cout << "       --> High-level encrypt/decrypt wrappers PASSED!" << std::endl;
}

void test_error_handling_and_tampering() {
    std::cout << "[TEST] 5. Error Handling, Strict Padding Validation, & Tamper Resistance..." << std::endl;

    std::string key = "MySecretKey_1234";
    std::string valid_msg = "Confidential chat payload between Alice and Bob";
    std::string enc_hex = encrypt(valid_msg, key);

    // 1. Wrong key must throw invalid_argument ("Invalid padding")
    bool caught_wrong_key = false;
    try {
        decrypt(enc_hex, "WrongSecretKey99");
    } catch (const std::invalid_argument &e) {
        caught_wrong_key = true;
    }
    assert(caught_wrong_key);

    // 2. Tampered ciphertext byte must fail padding validation
    std::string tampered_hex = enc_hex;
    // Flip a hex char in the ciphertext portion
    tampered_hex[tampered_hex.size() - 2] = (tampered_hex[tampered_hex.size() - 2] == '0') ? '1' : '0';
    bool caught_tamper = false;
    try {
        decrypt(tampered_hex, key);
    } catch (const std::invalid_argument &e) {
        caught_tamper = true;
    }
    assert(caught_tamper);

    // 3. Invalid key length (not 16, 24, 32)
    bool caught_invalid_key_len = false;
    try {
        AES bad_aes("short_key_7B");
    } catch (const std::invalid_argument &e) {
        caught_invalid_key_len = true;
    }
    assert(caught_invalid_key_len);

    // 4. Invalid block length for encrypt_block
    AES good_aes(key);
    bool caught_invalid_block = false;
    try {
        std::vector<unsigned char> bad_block = {1, 2, 3};
        good_aes.encrypt_block(bad_block);
    } catch (const std::invalid_argument &e) {
        caught_invalid_block = true;
    }
    assert(caught_invalid_block);

    // 5. Odd length hex ciphertext
    bool caught_odd_hex = false;
    try {
        decrypt("abc", key);
    } catch (const std::invalid_argument &e) {
        caught_odd_hex = true;
    }
    assert(caught_odd_hex);

    std::cout << "       --> All error handling & tamper tests PASSED!" << std::endl;
}

int main() {
    std::cout << "=========================================================" << std::endl;
    std::cout << "   RUNNING AES-128 / AES-192 / AES-256 UNIT TEST SUITE   " << std::endl;
    std::cout << "=========================================================" << std::endl;

    test_nist_aes128_known_answer_vectors();
    test_fips197_aes192_and_aes256_vectors();
    test_cbc_mode_and_padding_lengths();
    test_high_level_encrypt_and_decrypt();
    test_error_handling_and_tampering();

    std::cout << "=========================================================" << std::endl;
    std::cout << "   ALL UNIT TESTS PASSED SUCCESSFULLY! (100% VERIFIED)   " << std::endl;
    std::cout << "=========================================================" << std::endl;

    return 0;
}