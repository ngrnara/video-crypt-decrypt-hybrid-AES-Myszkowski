<div align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" />
  <img src="https://img.shields.io/badge/Kripto-AES%2BMyszkowski-green?style=for-the-badge" />

  <h1 style="color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 10px;">
    🛡️ Hybrid Crypto-Video Encryption
  </h1>
  <h2 style="font-weight: 300; margin-top: -10px;">
    AES-GCM (Modern) + Myszkowski Cipher (Klasik)
  </h2>
</div>

<p align="center">
  Proyek Tugas Akhir Kriptografi untuk pengamanan file video berukuran besar menggunakan skema enkripsi <b>Hybrid</b>.<br>
  <i>(Memenuhi Syarat Min. 2 Algoritma dan File Video)</i>
</p>

---

## 🎯 Tujuan dan Arsitektur Proyek

<div style="display: flex; justify-content: space-between; gap: 20px;">
  <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; flex: 1;">
    <h4 style="color: #ff4b4b;">Komponen Utama</h4>
    <ul>
      <li><b>AES-256-GCM:</b> Algoritma Modern (Simetris) untuk Enkripsi Konten File (Data video). Dipilih karena kecepatan dan jaminan Integritas Data (Tag).</li>
      <li><b>Myszkowski Cipher:</b> Algoritma Klasik (Transposisi) untuk <i>Key Wrapping</i> Kunci Sesi AES. Dipilih karena merupakan cipher Transposisi (bukan substitusi).</li>
      <li><b>Streamlit:</b> Digunakan sebagai antarmuka GUI wajib untuk demo yang <i>user-friendly</i> dan pengukuran waktu proses.</li>
    </ul>
  </div>
  <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; flex: 1;">
    <h4 style="color: #17a2b8;">Fitur Kinerja</h4>
    <p>Aplikasi ini dirancang untuk menangani file video berukuran besar dengan menggunakan teknik <b>Chunking (64 KB)</b> pada proses enkripsi dan dekripsi (kode di <code>crypto_hybrid.py</code>). Ini mencegah <b>Memory Overflow</b> pada server <i>cloud</i> (Streamlit Cloud).</p>
    <p>File output memiliki ekstensi kustom <b><code>.hybr</code></b>.</p>
  </div>
</div>

---

### 🧱 Format File Output (`.hybr`)

File terenkripsi (`.hybr`) memiliki struktur *header* biner yang spesifik untuk memfasilitasi dekripsi:

<pre>
[Magic: HYBR] 
+ [Versi]
+ [Panjang Kunci Enkripsi]
+ [Kunci Myszkowski Ciphertext (Hex)]
+ [Nonce AES]
+ [Ciphertext Konten]
+ [GCM Tag]
</pre>

---

## ⚙️ Persiapan dan Instalasi

### 1️⃣ Struktur Proyek

Pastikan semua file berada di *root directory* proyek Anda:

```
video-crypto-hybrid/
├─ crypto_hybrid.py       # Logika inti AES-GCM dan Myszkowski
├─ streamlit_app.py       # Streamlit GUI
├─ cli.py                 # Command Line Interface (opsional)
├─ bench.py               # Benchmark waktu & throughput
├─ requirements.txt       # Daftar dependensi
└─ README.md              # File dokumentasi ini
```

---

### 2️⃣ Instalasi Dependensi

Aktifkan **Virtual Environment** Anda (contoh di Windows):

```bash
.env\Scripts\Activate.ps1
```

Kemudian install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🚀 Cara Menjalankan Aplikasi

### 🖥️ A. Via Streamlit (GUI - Disarankan)

Jalankan perintah berikut di terminal:

```bash
python -m streamlit run streamlit_app.py
```

Aplikasi akan terbuka di browser:
> 🌐 http://localhost:8501

---

### ☁️ B. Via Streamlit Cloud (Deployment Publik)

Langkah-langkah:
1. Push semua kode ke repositori GitHub publik.
2. Login ke [Streamlit Cloud](https://streamlit.io/cloud)
3. Klik **New App** → pilih repositori ini.
4. Pilih file utama: `streamlit_app.py`
5. Klik **Deploy**

Streamlit akan otomatis membangun environment dan menjalankan aplikasi Anda.

---

## 🧪 C. Pengujian Integritas Data 

Untuk membuktikan data tidak rusak setelah dekripsi, lakukan verifikasi *hash* file menggunakan **SHA-256**.

1. **Enkripsi File Asli**
   ```bash
   python cli.py enc original.mp4 original.hybr --key "password"
   ```

2. **Dekripsi File**
   ```bash
   python cli.py dec original.hybr recovered.mp4 --key "password"
   ```

3. **Verifikasi Integritas**
   ```bash
   sha256sum original.mp4 recovered.mp4
   ```
   <p align="center" style="color:red;">
     <b>HASH kedua file harus sama persis!</b><br>
     Ini membuktikan integritas data dan validasi tag AES-GCM.
   </p>

---

## 📊 D. Benchmark Kinerja

Gunakan `bench.py` untuk mengukur waktu dan throughput enkripsi/dekripsi:

```bash
python bench.py
```

Hasil:
- `bench_out/bench_results.csv` — tabel waktu & kecepatan
- `bench_out/bench_plot.png` — grafik performa

---

## 📘 E. Penjelasan Keamanan

- **AES-GCM** menjamin kerahasiaan + integritas (authenticated encryption).  
- **Myszkowski Transposition** digunakan hanya untuk *key wrapping* (tidak mengganti karakter, hanya menukar posisi).  
- Kombinasi ini **memenuhi syarat minimal 2 algoritma** tanpa melanggar larangan *substitusi*.

---

<div align="center">
  <p style="margin-top: 20px; font-style: italic;">
    Dibuat dengan ❤️ menggunakan Python dan Kriptografi<br>
    untuk penyelesaian Tugas Proyek Akhir.
  </p>
</div>
