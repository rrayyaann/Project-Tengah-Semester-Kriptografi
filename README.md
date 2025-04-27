# Project-Tengah-Semester-Kriptografi
### Kelompok 7 (Kriptografi A)
| Nama | NRP |
|---------|---------|
| Daffa Rajendra Priyatama | 5027231009   |
| Muhamad Arrayyan | 5027231014   |
| Naufal Syafi' Hakim | 5027231022   |
| RM. Novian Malcolm Bayuputra | 5027231035   |
| Dzaky Faiq Fayyadhi | 5027231047   |
# Mini-AES 16-bit
---

## Fitur

- Enkripsi dan Dekripsi
- Proses Ekspansi Kunci
- Mode operasi blok (ECB dan CBC)
- Pengujian Efek Avalanche
- GUI Interface
- Terdapat log proses

---

## Mini-AES

### Spesifikasi 

- Ukuran Blok: 16 bit (4 nibble)
- Ukuran Key: 16 bit (4 nibble)
- Jumlah Round: 3 round

### Proses Enkripsi Setiap Round

1. SubNibbles: Setiap 4-bit nibble diganti menggunakan tabel substitusi (S-box).
2. ShiftRows: Baris-baris grid digeser posisinya.
3. MixColumns: Mencampur kolom menggunakan operasi di Galois Field (GF(2⁴) (16 bit)).
4. AddRoundKey: XOR dengan round key.

### Key Expansion

  - Rotasi bagian terakhir key
  - Substitusi menggunakan S-box
  - XOR dengan Rcon
  - Gabungkan hasilnya untuk menghasilkan key baru

---

## Flowchart 
### Mini-AES

```
┌─────────────────┐
│   Plaintext     │
└────────┬────────┘
         ▼
┌─────────────────┐
│Initial AddRoundKey│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Round 1-2:    │
│   SubNibbles    │
│   ShiftRows     │
│   MixColumns    │
│   AddRoundKey   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Final Round:  │
│   SubNibbles    │
│   ShiftRows     │
│   AddRoundKey   │
└────────┬────────┘
         ▼
┌─────────────────┐
│   Ciphertext    │
└─────────────────┘
```

### Key Expansion 

```
┌─────────────────┐
│    Key awal     │
└────────┬────────┘
         │
         ▼
┌──────────────────────────────┐
│Setiap round :                │
│1. Rotate baris terakhir      │
│2. Subtitusi S-box            │
│3. XOR dengan Rcon            │
└────────────────┬─────────────┘
                 │
                 ▼
┌─────────────────────────────┐
│      Round Keys (K0-K3)     │
└─────────────────────────────┘
```

---

## Test Case

| Plaintext | Kunci   | Ciphertext yang Diharapkan |
|-----------|---------|----------------------------|
| 0x1234    | 0xABCD  | 0xB6F9                     |
| 0x0000    | 0xFFFF  | 0x931C                     |
| 0x5A5A    | 0xA5A5  | 0x7AF9                     |

### Test Case 1

Hasil expansion key
Round keys: ['0xabcd', '0x579a', '0x75ef', '0x3ad5']

Initial AddRoundkey 
0x1234 XOR 0xabcd
0xb9f9

Round 1:
SubNibbles
SBOX = [
        0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7
    ]
0xb9f9 disubtitusikan menjadi 0x3272

ShiftRows
|a|c| 
|----------|---------| 
| b| d| 
menjadi
| a|c| 
| d| b| 

maka
| 3|7| 
|----------|---------|
| 2| 2|
menjadi
| 3|7| 
| 2| 2|

Setelah shiftrows menjadi 0x3272

MixColumns
MIX_COL_MATRIX = [
        [3, 2],
        [2, 3]
    ]
Dilakukan perkalian matriks, hasilnya 0xbefd

AddRoundKey
0xbefd XOR 0x579a
0xe967

Round 2:
SubNibbles
0xe967 disubtitusi dengan Sbox jadi 0xf285

ShiftRows
0xf285 dishift jadi 0xf582

MixColumns
0xf582 dilakukan mixcolumn hasilnya 0x8c04

AddRoundkey
0x8c04 XOR 0x75ef
0xf9eb

Round 3:
SubNibbles
0xf9eb disubtitusi hasilnya 0x72f3

ShiftRows
0x72f3 dishift hasilnya 0x73f2

AddRoundKey
0x73f2 XOR 0x3ad5
0x4927

### Test Case 2

![image](https://github.com/user-attachments/assets/7114324c-3e72-4f9e-a7ee-41eb00c10ef3)

### Test Case 3

![image](https://github.com/user-attachments/assets/8c80fed5-5d74-4f6f-a83b-02f8949a68ac)

---
## Kelebihan Mini-AES 

- Mudah dipahami untuk belajar tentang AES
- Ukuran keynya kecil sehingga cepat saat dijalankan
- Ukuran key dan data yang kecil sehingga cocok untuk digunakan device yang terbatas sumber dayanya

---
## Kelemahan Mini-AES

- Ukuran kunci hanya 16-bit, sangat mudah untuk brute-force
- Hanya 3 round, perlindungan jauh lebih lemah dibandingkan AES asli.
- Terbatas dalam skalabilitas, tidak cocok untuk data yang besar.

---

