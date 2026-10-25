#include "crypto/aes.hpp"
#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>
#include <random>
#define uc unsigned char

uc s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

uc inverse_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

uc round_constant[32] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
};

std::string text2hex (std::string s){
    std::string hex = "0123456789abcdef";
    std::string res = "";

    for (uc c : s){
        res += hex[c/16];
        res += hex[c%16];
    }
    return res;
}

std::string hex2text (std::string s){
    std::string res = "";

    for (std::size_t i = 0; i < s.size(); i += 2){
        std::string byte_str = s.substr(i, 2);
        char c = char(std::stoi(byte_str, nullptr, 16));

        res += c;
    }
    return res;
}
std::vector<unsigned char> remove_padding(std::vector<unsigned char> s);

std::vector<uc> add_padding(std::vector<uc> s){
    int padding = 16 - (s.size() % 16);
    for (int i = 0; i<padding; i++){
        s.push_back((uc) padding);
    }
    return s;
}

std::vector<uc> remove_padding(std::vector<uc> s){
    if (s.empty()){
        return s;
    }
    int padding = (int) s.back();
    if (padding < 1 || padding > 16){
        throw std::invalid_argument("Invalid padding");
    }
    for (int i = 0; i<padding; i++){
        if (s[s.size() - 1 - i] != (uc) padding){
            throw std::invalid_argument("Invalid padding");
        }
    }
    s.resize(s.size() - padding);
    return s;
}

std::vector<std::vector<uc>> bytes2matrix (std::vector<uc> text){
    std::vector<std::vector<uc>> mat(4, std::vector<uc>(4));
    for (int i = 0; i<4; i++){
        for (int j = 0; j<4; j++){
            mat[i][j] = text[i*4+j];
        }
    }
    return mat;
}

std::vector<uc> matrix2bytes (std::vector<std::vector<uc>> mat){
    std::vector<uc> text;
    for (int i = 0; i<4; i++){
        for (int j = 0; j<4; j++){
            text.push_back(mat[i][j]);
        }
    }
    return text;
}

void add_round_key (std::vector<std::vector<uc>> & s, std::vector<uc> & k){
    for (int i = 0; i<4; i++){
        for (int j = 0; j<4; j++){
            s[i][j] ^= k[i * 4 + j];
        }
    }
}

void sub_bytes (std::vector<std::vector<uc>> & s, bool inverse = false){
    for (int i = 0; i<4; i++){
        for (int j = 0; j<4; j++){
            if (!inverse){
                s[i][j] = s_box[s[i][j]];
            }
            else{
                s[i][j] = inverse_s_box[s[i][j]];
            }
        }
    }
}

void shift_rows (std::vector<std::vector<uc>> &s, bool inverse = false){
    uc temp;
    if (!inverse){ //geser kiri
        //baris 1
        temp = s[0][1]; 
        s[0][1] = s[1][1]; 
        s[1][1] = s[2][1]; 
        s[2][1] = s[3][1]; 
        s[3][1] = temp;

        //baris 2
        std::swap(s[0][2], s[2][2]); 
        std::swap(s[1][2], s[3][2]);

        //baris 3
        temp = s[3][3]; 
        s[3][3] = s[2][3]; 
        s[2][3] = s[1][3]; 
        s[1][3] = s[0][3]; 
        s[0][3] = temp;
    }
    else{ //geser kanan
        //baris 1
        temp = s[3][1]; 
        s[3][1] = s[2][1]; 
        s[2][1] = s[1][1]; 
        s[1][1] = s[0][1]; 
        s[0][1] = temp;

        //baris 2
        std::swap(s[0][2], s[2][2]); 
        std::swap(s[1][2], s[3][2]);
        
        //baris 3
        temp = s[0][3]; 
        s[0][3] = s[1][3]; 
        s[1][3] = s[2][3]; 
        s[2][3] = s[3][3]; 
        s[3][3] = temp;
    }
}

uc xtime(uc a) {
    if (a & 128){ // MSB = 1 ? 
        return ((a << 1) ^ 27) & 255; //reduksi bit agar tetap 8 bit
    }
    return (a << 1) & 255;
}

void mix_single_column (std::vector<uc> & a){
    uc all = a[0] ^ a[1] ^ a[2] ^ a[3];
    uc a0 = a[0];
    a[0] ^= all ^ xtime(a[0] ^ a[1]);
    a[1] ^= all ^ xtime(a[1] ^ a[2]);
    a[2] ^= all ^ xtime(a[2] ^ a[3]);
    a[3] ^= all ^ xtime(a[3] ^ a0);
}

void mix_columns(std::vector<std::vector<uc>> & mat, bool inverse=false){
    if (inverse) {
        for (int i = 0; i < 4; i++) {
            uc u = xtime(xtime(mat[i][0] ^ mat[i][2]));
            uc v = xtime(xtime(mat[i][1] ^ mat[i][3]));
 
            mat[i][0] ^= u;
            mat[i][1] ^= v;
            mat[i][2] ^= u;
            mat[i][3] ^= v;
        }
    }
    for (int i = 0; i<4; i++){
        mix_single_column(mat[i]);
    }
}

std::vector<uc> xor_bytes(std::vector<uc> a, std::vector<uc> b){
    std::vector<uc> res;
    for (std::size_t i = 0; i < a.size(); i++){
        res.push_back(a[i] ^ b[i]);
    }
    return res;
}

void AES::expand_key (std::vector<uc> master_key){
    int sz = master_key.size();

    if (sz != 16 && sz != 24 && sz != 32){
        throw std::invalid_argument("AES key must be 16, 24, or 32 bytes");
    }

    int nk = sz / 4; // aes-128: 4, aes-192: 6, aes-256: 8
    n_rounds = nk + 6;
    int total = (n_rounds + 1) * 4;
    
    std::vector<std::vector<uc>> key_cols;

    for (int i = 0; i<sz; i+=4){
        key_cols.push_back({master_key[i], master_key[i+1], master_key[i+2], master_key[i+3]});
    }
    for (int i = nk; i<total; i++){
        std::vector<uc> word = key_cols[i-1]; // w3

        if (i % nk == 0){
            std::rotate(word.begin(), word.begin() + 1, word.end());

            for (int j = 0; j<4; j++){
                word[j] = s_box[word[j]];
            }
            word[0] ^= round_constant[i/nk];
        }
        else if (nk == 8 && i % nk == 4){
            for (int j = 0; j<4; j++){
                word[j] = s_box[word[j]];
            }
        }
        key_cols.push_back(xor_bytes(key_cols[i-nk], word));
    }

    round_keys.clear();
    for (int r = 0; r<=n_rounds; r++){
        std::vector<uc> round_key;

        for (int i = 0; i<4; i++){
            for (int j = 0; j<4; j++){
                round_key.push_back(key_cols[r * 4 + i][j]);
            }
        }
        round_keys.push_back(round_key);
    }
}

AES::AES(std::string key) {
    this->key_size = key.size();
    std::vector<uc> key_bytes(key.begin(), key.end());
    expand_key(key_bytes);
}
AES::AES(std::vector<uc> key_bytes) {
    this->key_size = key_bytes.size();
    expand_key(key_bytes);
}

std::vector<uc> AES::encrypt_block (std::vector<uc> plaintext){
    if (plaintext.size() != 16){
        throw std::invalid_argument("Plaintext block must be exactly 16 bytes.");
    }
    std::vector<std::vector<uc>> state = bytes2matrix(plaintext);

    add_round_key(state, round_keys[0]);

    for (int i = 1; i<n_rounds; i++){
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys[i]);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys[n_rounds]);

    return matrix2bytes(state);
}

std::vector<uc> AES::decrypt_block (std::vector<uc> ciphertext){
    if (ciphertext.size() != 16){
        throw std::invalid_argument("Ciphertext block must be exactly 16 bytes.");
    }
    std::vector<std::vector<uc>> state = bytes2matrix(ciphertext);

    add_round_key(state, round_keys[n_rounds]);
    shift_rows(state, true);
    sub_bytes(state, true);

    for (int i = n_rounds-1; i>=1; i--){
        add_round_key(state, round_keys[i]);
        mix_columns(state, true);
        shift_rows(state, true);
        sub_bytes(state, true);
    }
    add_round_key(state, round_keys[0]);

    return matrix2bytes(state);
}

std::vector<uc> AES::encrypt_cbc (std::vector<uc> plaintext, std::vector<uc> iv){
    if (iv.size() != 16){
        throw std::invalid_argument("IV must be exactly 16 bytes");
    }
    plaintext = add_padding(plaintext);

    std::vector<uc> ciphertext;
    std::vector<uc> prev = iv;

    int sz = plaintext.size();
    for (int i=0; i<sz; i+=16){
        std::vector<uc> block(plaintext.begin() + i, plaintext.begin() + i + 16);
        block = xor_bytes(block, prev);
        block = encrypt_block(block);

        ciphertext.insert(ciphertext.end(), block.begin(), block.end());
        prev = block;
    }
    return ciphertext;
}

std::vector<uc> AES::decrypt_cbc (std::vector<uc> ciphertext, std::vector<uc> iv){
    if (iv.size() != 16){
        throw std::invalid_argument("IV must be exactly 16 bytes");
    }
    if (ciphertext.empty() || ciphertext.size() % 16 != 0){
        throw std::invalid_argument("Ciphertext must be a non-empty multiple of 16 bytes");
    }

    std::vector<uc> decrypted;
    std::vector<uc> prev = iv;

    int sz = ciphertext.size();
    for (int i = 0; i<sz; i+=16){
        std::vector<uc> block(ciphertext.begin() + i, ciphertext.begin() + i + 16);
        std::vector<uc> pt = decrypt_block(block);
        pt = xor_bytes(pt, prev);

        decrypted.insert(decrypted.end(), pt.begin(), pt.end());
        prev = block;
    }
    return remove_padding(decrypted);
}

std::string encrypt(std::string plaintext, std::string key, std::string iv){
    std::vector<uc> iv_bytes;
    if (iv.empty()){
        std::random_device rd;
        for (int i = 0; i < 16; i++) {
            iv_bytes.push_back(static_cast<uc>(rd() & 0xFF));
        }
    }
    else{
        if (iv.size() != 16) {
            throw std::invalid_argument("IV must be exactly 16 bytes");
        }
        iv_bytes.assign(iv.begin(), iv.end());
    }
    std::vector<uc> pt_bytes(plaintext.begin(), plaintext.end());
    AES aes(key);
    std::vector<uc> ct_bytes = aes.encrypt_cbc(pt_bytes, iv_bytes);

    std::string text(iv_bytes.begin(), iv_bytes.end());
    text.append(ct_bytes.begin(), ct_bytes.end());

    return text2hex(text);
}

std::string decrypt(std::string ciphertext, std::string key, std::string iv){
    if (ciphertext.size() % 2 != 0) {
        throw std::invalid_argument("Ciphertext hex length must be even");
    }
    std::string raw_bytes = hex2text(ciphertext);
    std::vector<uc> iv_bytes;
    std::vector<uc> ct_bytes;

    if (iv.empty()){
        if (raw_bytes.size() < 32){
            throw std::invalid_argument("Ciphertext payload too short");
        }
        iv_bytes.assign(raw_bytes.begin(), raw_bytes.begin() + 16);
        ct_bytes.assign(raw_bytes.begin() + 16, raw_bytes.end());
    }
    else{
        if (iv.size() != 16){
            throw std::invalid_argument("IV must be exactly 16 bytes");
        }
        iv_bytes.assign(iv.begin(), iv.end());
        ct_bytes.assign(raw_bytes.begin(), raw_bytes.end());
    }
    AES aes(key);
    std::vector<uc> pt_bytes = aes.decrypt_cbc(ct_bytes, iv_bytes);

    return std::string(pt_bytes.begin(), pt_bytes.end());
}
