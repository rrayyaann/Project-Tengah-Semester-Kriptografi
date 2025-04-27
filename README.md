---

# Project Tengah Semester - Kriptografi

# Mini-AES 16-bit

Mini-AES adalah versi kecil dan sederhana dari algoritma enkripsi terkenal, AES. Jika biasanya AES ribet dan berat, Mini-AES hanya memakai **blok 16-bit** dan **kunci 16-bit**, jadi jauh lebih mudah buat belajar konsep dasarnya.

---

## Fitur Utama

- Enkripsi dan dekripsi Mini-AES lengkap
- Proses perluasan kunci
- Bisa pakai mode operasi blok: **ECB** dan **CBC**
- Tes **efek avalanche** (perubahan kecil → hasil berubah drastis)
- Ada **antarmuka GUI** — jadi nggak perlu repot pakai command line
- Bisa **input/output lewat file**
- Ada log proses biar bisa lihat langkah-langkahnya

---

## Cara Kerja Mini-AES

### Spesifikasi Dasar

- **Ukuran blok**: 16 bit (dibentuk jadi grid 2x2 yang isinya potongan 4-bit)
- **Ukuran kunci**: 16 bit
- **Jumlah ronde**: 3 ronde enkripsi

### Apa yang Terjadi di Tiap Ronde

1. **SubNibbles**: Tiap potongan 4-bit diganti berdasarkan tabel khusus (S-box).
2. **ShiftRows**: Baris-baris dalam grid digeser (swap sederhana).
3. **MixColumns**: Kolom-kolom dicampur pakai operasi khusus di Galois Field (GF(2⁴)).
4. **AddRoundKey**: Hasil sementara di-XOR dengan kunci ronde.

Catatan: Di ronde terakhir, tahap MixColumns dilewati.

### Ekspansi Kunci

Supaya lebih aman, kunci awal dikembangkan jadi 4 kunci baru.  
Langkahnya:

- Putar bagian akhir kunci
- Ganti nilainya pakai S-box
- XOR dengan konstanta ronde
- Gabungkan hasilnya buat kunci baru

---

## Alur Proses Enkripsi

| Tahap | Operasi |
|-------|---------|
| Mulai | Masukkan Plaintext |
| Tahap 1 | AddRoundKey (pakai kunci awal) |
| Tahap 2 (Ronde 1) | SubNibbles → ShiftRows → MixColumns → AddRoundKey |
| Tahap 3 (Ronde 2) | SubNibbles → ShiftRows → MixColumns → AddRoundKey |
| Tahap 4 (Ronde Akhir) | SubNibbles → ShiftRows → AddRoundKey |
| Selesai | Dapat Ciphertext |

---

## Contoh Uji

| Plaintext | Kunci  | Ciphertext yang Diharapkan |
|-----------|--------|----------------------------|
| 0x1234    | 0xABCD | 0xB6F9                     |
| 0x0000    | 0xFFFF | 0x7892                     |
| 0x5A5A    | 0xA5A5 | 0x3C6D                     |

---

## Cara Menjalankan

1. Jalankan file Python utama (misal `python main.py`, atau klik file di IDE seperti VS Code atau PyCharm).
2. Aplikasi GUI akan langsung terbuka.
3. Pilih mau operasi:
   - Enkripsi/Dekripsi satu blok
   - Enkripsi/Dekripsi banyak blok sekaligus
4. Masukkan **Plaintext** dan **Kunci** dalam format hex (contoh: `0x1234`).
5. Tekan tombol proses.
6. Hasil enkripsi atau dekripsi beserta semua langkahnya akan muncul.

---

## Fitur Tambahan

- Bisa pilih mode ECB atau CBC untuk multi-blok
- Tes efek avalanche:
  - Lihat bagaimana perubahan kecil di input bisa ngubah hasilnya total
- Bisa buka file plaintext dan simpan ciphertext
- Ada log lengkap semua tahapan enkripsi/dekripsi, dari SubNibbles sampai AddRoundKey

---

## Kenapa Mini-AES Menarik

- Sangat gampang dipahami, cocok buat belajar dasar enkripsi.
- Prosesnya cepat dan ringan.
- Efek avalanche-nya kelihatan jelas, walaupun ukuran datanya kecil.

---

## Kelemahan Mini-AES

- Ukuran kunci kecil (16-bit) gampang banget di-brute-force.
- Cuma 3 ronde, jauh lebih lemah dibanding AES asli.
- Operasinya disederhanakan, jadi kurang aman.
- Mini-AES **tidak cocok dipakai untuk enkripsi data penting** di dunia nyata.

---
