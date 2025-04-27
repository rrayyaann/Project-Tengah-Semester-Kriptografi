# Project-Tengah-Semester-Kriptografi

# Mini-AES 16-bit

Mini-AES adalah versi kecil dan sederhana dari AES (Advanced Encryption Standard) yang terkenal.  
Mini-AES bekerja dengan **blok 16-bit** dan menggunakan **kunci 16-bit**, cocok untuk memahami dasar-dasar enkripsi tanpa kompleksitas berlebih.

---

## ✨ Fitur Utama

- Implementasi penuh Mini-AES (Enkripsi & Dekripsi)
- Proses Ekspansi Kunci
- Mode operasi blok: **ECB** dan **CBC**
- Pengujian **Efek Avalanche**
- **Antarmuka GUI** — tanpa perlu command line
- Dukungan untuk **input/output file**
- Log proses untuk melihat semua tahapan detail

---

## 🛠️ Cara Kerja Mini-AES

### Spesifikasi Dasar

- **Ukuran Blok**: 16 bit (dalam bentuk grid 2x2 nibble 4-bit)
- **Ukuran Kunci**: 16 bit
- **Jumlah Ronde**: 3 ronde enkripsi

### Proses Enkripsi Setiap Ronde

1. **SubNibbles**: Setiap 4-bit nibble diganti menggunakan tabel substitusi (S-box).
2. **ShiftRows**: Baris-baris grid digeser posisinya (swap sederhana).
3. **MixColumns**: Mencampur kolom menggunakan operasi di Galois Field (GF(2⁴)).
4. **AddRoundKey**: XOR dengan kunci ronde.

🔔 **Catatan**: Pada ronde terakhir, tidak ada MixColumns.

### Ekspansi Kunci

Untuk memperkuat enkripsi, kunci asli diperluas menjadi 4 kunci:

- **Langkah-langkah Ekspansi**:
  - Rotasi bagian terakhir kunci
  - Substitusi menggunakan S-box
  - XOR dengan konstanta ronde
  - Gabungkan hasilnya untuk menghasilkan kunci baru

---

## 🔥 Alur Proses Enkripsi
|Tahap | Operasi |
|-----------|---------|
|Mulai | Plaintext |
|Tahap 1 | AddRoundKey (menggunakan kunci awal) |
|Tahap 2 (Ronde 1) | SubNibbles → ShiftRows → MixColumns → AddRoundKey |
|Tahap 3 (Ronde 2) | SubNibbles → ShiftRows → MixColumns → AddRoundKey |
|Tahap 4 (Ronde Akhir) | SubNibbles → ShiftRows → AddRoundKey (tanpa MixColumns) |
|Selesai | Ciphertext |

---

## 🧪 Contoh Uji (Test Cases)

| Plaintext | Kunci   | Ciphertext yang Diharapkan |
|-----------|---------|----------------------------|
| 0x1234    | 0xABCD  | 0xB6F9                     |
| 0x0000    | 0xFFFF  | 0x7892                     |
| 0x5A5A    | 0xA5A5  | 0x3C6D                     |

---

## 📥 Cara Menjalankan

1. Buka file Python utama (`python main.py` atau klik file jika menggunakan IDE seperti VS Code / PyCharm).
2. Antarmuka aplikasi akan terbuka secara otomatis.
3. Pilih mode:
   - Enkripsi/Dekripsi satu blok
   - Enkripsi/Dekripsi beberapa blok
4. Masukkan **Plaintext** dan **Kunci** dalam format heksadesimal (contoh: `0x1234`).
5. Klik tombol untuk memulai proses.
6. Lihat hasil dan log langkah-langkahnya di layar.

---

## 📦 Fitur Tambahan

- **Mode ECB dan CBC** untuk pengolahan multi-blok
- **Pengujian Avalanche**:
  - Menunjukkan bagaimana perubahan kecil pada input menghasilkan perubahan besar pada output
- **Dukungan File**:
  - Bisa membuka file plaintext dan menyimpan hasil ciphertext
- **Log Proses Lengkap**:
  - Melihat semua tahapan seperti SubNibbles, ShiftRows, MixColumns, dan AddRoundKey secara detail

---

## ⚡ Kenapa Mini-AES Menarik

- **Mudah dipahami**: Tanpa kompleksitas AES besar.
- **Cepat dan ringan**: Cocok untuk belajar dasar enkripsi blok.
- **Menunjukkan efek avalanche**: Perubahan bit kecil memengaruhi seluruh output.

---

## ❌ Kelemahan Mini-AES (Tidak Aman untuk Dunia Nyata)

- Ukuran kunci hanya 16-bit ➔ sangat mudah untuk brute-force.
- Hanya 3 ronde ➔ perlindungan jauh lebih lemah dibandingkan AES asli.
- Operasi disederhanakan ➔ mudah dianalisis.
- **Jangan gunakan Mini-AES untuk enkripsi data sensitif di dunia nyata.**

---

