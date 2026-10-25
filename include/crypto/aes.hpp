#ifndef AES_HPP
#define AES_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#define uc unsigned char

std::string text2hex (std::string s);
std::string hex2text (std::string s);

std::vector<uc> add_padding(std::vector<uc> s);
std::vector<uc> remove_padding(std::vector<uc> s);

class AES {
    public:
        AES (std::string key);
        AES (std::vector<uc> key_bytes);

        std::vector<uc> encrypt_block (std::vector<uc> plaintext);
        std::vector<uc> decrypt_block (std::vector<uc> ciphertext);
        std::vector<uc> encrypt_cbc (std::vector<uc> plaintext, std::vector<uc> iv);
        std::vector<uc> decrypt_cbc (std::vector<uc> ciphertext, std::vector<uc> iv);

        int get_rounds(){
            return n_rounds;
        }
        int get_key_size(){
            return key_size;
        }

    private:
        int key_size;
        int n_rounds;

        std::vector<std::vector<uc>> round_keys;

        void expand_key (std::vector<uc> master_key);
};

std::string encrypt(std::string plaintext, std::string key, std::string iv="");
std::string decrypt(std::string ciphertext, std::string key, std::string iv="");

#endif