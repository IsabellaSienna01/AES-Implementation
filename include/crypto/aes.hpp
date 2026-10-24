#ifndef AES_HPP
#define AES_HPP

#include <string>
#include <vector>
#define uc unsigned char
using namespace std;

string text2hex (string s);
string hex2text (string s);

vector<uc> add_padding(vector<uc> s);
vector<uc> remove_padding(vector<uc> s);

class AES {
    public:
        AES (string key);
        AES (vector<uc> key_bytes);

        vector<uc> encrypt_block (vector<uc> plaintext);
        vector<uc> decrypt_block (vector<uc> ciphertext);
        vector<uc> encrypt_cbc (vector<uc> plaintext, vector<uc> iv);
        vector<uc> decrypt_cbc (vector<uc> ciphertext, vector<uc> iv);

        int get_rounds(){
            return n_rounds;
        }
        int get_key_size(){
            return key_size;
        }

    private:
        int key_size;
        int n_rounds;

        vector<vector<uc>> round_keys;

        void expand_key (vector<uc> master_key);
};

string encrypt(string plaintext, string key, string iv="");
string decrypt(string ciphertext, string key, string iv="");

#endif
