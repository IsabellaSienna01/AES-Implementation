# PROJECT CONTRACT — Secure Key Distribution & Messaging

**Bahasa:** Modern C++20  
**Build system:** CMake  
**Arsitektur:** KDC + Alice + Bob  
**Transport:** TCP sockets  
**Protokol:** Needham–Schroeder-style key distribution sesuai spesifikasi tugas  
**Algoritma komunikasi:** AES-128 manual

## 1. Tujuan proyek

Membangun aplikasi komunikasi jaringan antara Alice dan Bob melalui distribusi kunci sesi oleh KDC. Setelah distribusi kunci dan autentikasi berhasil, Alice dan Bob harus dapat bertukar pesan secara dua arah menggunakan AES.

## 2. Ketentuan wajib

1. KDC, Alice, dan Bob berjalan sebagai tiga entitas logis terpisah dengan tiga alamat IP berbeda.
2. Alice dan Bob harus dapat berperan sebagai sender sekaligus receiver.
3. AES dan logika KDC diimplementasikan secara manual.
4. Kunci dan plaintext yang ditampilkan kepada pengguna menggunakan format ASCII; ciphertext ditampilkan dalam hexadecimal.
5. Kunci tidak boleh ditetapkan permanen di source code. Kunci dapat dimasukkan atau dikonfigurasi saat runtime.
6. Setiap pesan jaringan memiliki format yang disepakati dan dapat diparsing secara deterministik.
7. Pesan aplikasi tidak boleh diproses sebagai pesan terautentikasi sebelum tahap autentikasi selesai.
8. Semua modul wajib dapat di-build melalui satu konfigurasi CMake.
9. Library eksternal tidak boleh menggantikan implementasi inti AES atau logika KDC. Library untuk socket, build, dan utilitas non-kriptografi diperbolehkan.

## 3. Pembagian kepemilikan modul

### Anggota A
- Implementasi AES-128 manual dan key expansion.
- Antarmuka enkripsi/dekripsi AES.
- Unit tests AES dengan test vector standar.
- Implementasi Alice dan alur initiator.
- Pengujian enkripsi/dekripsi pesan Alice.

### Anggota B
- Implementasi logika KDC dan distribusi kunci.
- Implementasi Bob dan alur responder.
- TCP transport, framing, konfigurasi endpoint, serta penanganan koneksi.
- Unit tests KDC dan protokol.
- Pengujian komunikasi dua arah pada Bob.

### Tanggung jawab bersama
- Menyetujui kontrak antarmuka sebelum implementasi paralel.
- Mengintegrasikan seluruh modul.
- Menguji komunikasi pada tiga IP berbeda.
- Menguji distribusi kunci, autentikasi, dan komunikasi AES end-to-end.
- Menulis README, dokumentasi protokol, serta panduan demonstrasi.
- Melakukan code review silang sebelum pengumpulan.

## 4. Aturan antarmuka

- Semua modul menggunakan tipe data dan format serialisasi yang disepakati.
- Fungsi kriptografi tidak melakukan operasi jaringan.
- Modul jaringan tidak mengimplementasikan algoritma AES sendiri.
- KDC tidak bergantung pada implementasi Alice atau Bob.
- Semua komunikasi jaringan menggunakan framing yang jelas; satu pemanggilan `send()` tidak diasumsikan sama dengan satu pesan lengkap.
- Setiap perubahan interface harus disetujui kedua anggota dan diuji ulang.

## 5. Definisi selesai (Definition of Done)

Suatu modul dianggap selesai jika:
- Dapat di-build tanpa error.
- Memiliki unit test yang relevan.
- Mematuhi header/interface bersama.
- Tidak menggunakan implementasi kriptografi eksternal untuk menggantikan algoritma wajib.
- Menangani input invalid dan kegagalan operasi dengan error yang jelas.
- Tidak merusak modul lain saat diintegrasikan.

## 6. Kesepakatan kerja

- Setiap anggota melakukan commit terpisah dengan pesan commit yang jelas.
- Perubahan pada header bersama tidak boleh dilakukan sepihak.
- Modul harus dapat diuji menggunakan mock atau test harness sebelum integrasi penuh.
- Fitur tambahan hanya dikerjakan setelah semua fitur wajib berhasil.
- Konflik integrasi diselesaikan dengan memprioritaskan kontrak bersama, bukan mengubah interface secara sepihak.

## 7. Struktur Direktori

```

secure-messaging/
├── CMakeLists.txt
├── README.md
├── config/
│   └── example.conf
├── docs/
│   ├── PROTOCOL.md
│   └── INTERFACE_CONTRACT.md
├── include/
│   ├── crypto/
│   │   └── aes.hpp
│   ├── protocol/
│   │   ├── messages.hpp
│   │   └── serialization.hpp
│   ├── network/
│   │   ├── tcp_connection.hpp
│   │   └── framing.hpp
│   └── common/
│       ├── result.hpp
│       └── config.hpp
├── src/
│   ├── crypto/
│   │   └── aes.cpp
│   ├── kdc/
│   │   ├── kdc.hpp
│   │   ├── kdc.cpp
│   │   └── main.cpp
│   ├── alice/
│   │   ├── alice.hpp
│   │   ├── alice.cpp
│   │   └── main.cpp
│   ├── bob/
│   │   ├── bob.hpp
│   │   ├── bob.cpp
│   │   └── main.cpp
│   ├── network/
│   │   └── tcp_connection.cpp
│   └── common/
│       └── serialization.cpp
└── tests/
    ├── aes_tests.cpp
    ├── protocol_tests.cpp
    └── integration_tests.cpp

```