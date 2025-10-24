# crypto_hybrid.py (Versi Final Lengkap)
import os
import streamlit as st # <-- Import Streamlit untuk debugging
import re              # <-- Import Regex untuk debugging & validasi
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------- Konstanta ----------
CHUNK = 64 * 1024  # 64KB, ukuran chunk untuk pemrosesan file
AES_TAG_LEN = 16   # Ukuran tag otentikasi GCM (16 byte)

# ---------- Fungsi Helper Myszkowski ----------
def _keyword_order(keyword: str):
    """
    Menghasilkan urutan peringkat numerik untuk setiap karakter dalam keyword
    berdasarkan urutan abjad uniknya. Huruf yang sama mendapat peringkat yang sama.
    Contoh: "BALLOON" -> [2, 1, 3, 3, 4, 4, 5] (A=1, B=2, L=3, N=4, O=5)
    """
    chars = list(keyword)
    unique_sorted = sorted(set(chars))
    rank_map = {c: i + 1 for i, c in enumerate(unique_sorted)} # Peringkat dimulai dari 1
    return [rank_map[c] for c in chars]

# ---------- Fungsi Myszkowski Cipher (Definisi SEBELUM digunakan) ----------
def myszkowski_encrypt(plaintext: str, keyword: str) -> str:
    """
    Mengenkripsi string (plaintext) menggunakan metode transposisi Myszkowski.
    Plaintext di sini diharapkan adalah representasi hex string dari kunci AES.
    """
    if not keyword:
        raise ValueError("Keyword diperlukan untuk Myszkowski")

    cols = len(keyword) # Jumlah kolom = panjang keyword
    # Membuat grid (daftar baris), plaintext diisi baris per baris
    rows = []
    for i in range(0, len(plaintext), cols):
        # Tambahkan padding karakter null ('\0') di akhir baris terakhir jika perlu
        rows.append(list(plaintext[i:i + cols].ljust(cols, '\0')))

    ranks = _keyword_order(keyword) # Dapatkan peringkat untuk setiap kolom

    # Dapatkan indeks kolom (0, 1, ..., cols-1)
    idxs = list(range(cols))
    # Urutkan indeks kolom berdasarkan (peringkat, lalu indeks asli)
    # Ini menentukan urutan pembacaan kolom sesuai aturan Myszkowski
    idxs_sorted = sorted(idxs, key=lambda i: (ranks[i], i))

    # Baca grid kolom per kolom sesuai urutan idxs_sorted
    result_chars = []
    for col in idxs_sorted:
        for r in range(len(rows)):
            ch = rows[r][col]
            # Hanya tambahkan karakter asli, abaikan padding null
            if ch != '\0':
                result_chars.append(ch)

    return ''.join(result_chars) # Gabungkan karakter menjadi ciphertext

def myszkowski_decrypt(ciphertext: str, keyword: str) -> str:
    """
    Mendekripsi ciphertext Myszkowski (Versi Revisi Perhitungan Kolom).
    Tujuannya adalah merekonstruksi hex string kunci AES asli (64 karakter).
    """
    if not keyword:
        raise ValueError("Keyword diperlukan untuk Myszkowski")

    cols = len(keyword) # Jumlah kolom = panjang keyword
    original_plaintext_len = 64 # Kunci AES 32 byte = 64 hex karakter

    # -- REKONSTRUKSI INFORMASI GRID ENKRIPSI --
    # Kita perlu tahu persis bagaimana grid dibuat saat enkripsi

    # Hitung jumlah baris yang digunakan saat enkripsi
    # (panjang asli + cols - 1) // cols adalah cara cepat menghitung ceil(panjang/cols)
    num_rows_encrypt = (original_plaintext_len + cols - 1) // cols

    # Hitung total sel dalam grid enkripsi
    grid_size_encrypt = num_rows_encrypt * cols

    # Hitung berapa banyak padding '\0' yang ditambahkan di akhir saat enkripsi
    padding_count_encrypt = grid_size_encrypt - original_plaintext_len

    # -- LOGIKA DEKRIPSI (MEMBACA CIPHERTEXT SESUAI URUTAN KOLOM) --
    ranks = _keyword_order(keyword) # Peringkat kolom
    idxs = list(range(cols))
    # Urutan kolom dibaca saat enkripsi (dan harus dibaca kembali saat dekripsi)
    idxs_sorted_by_rank = sorted(idxs, key=lambda i: (ranks[i], i))

    # Tentukan panjang aktual (jumlah karakter non-padding) untuk setiap kolom
    col_lengths_in_grid = {}
    for c in range(cols):
        # Awalnya, setiap kolom berisi 'num_rows_encrypt' karakter
        length = num_rows_encrypt
        # Jika kolom ini berada di posisi yang diisi padding di baris terakhir, kurangi panjangnya
        # Indeks sel terakhir di kolom c adalah (num_rows_encrypt - 1) * cols + c
        # Jika indeks ini >= panjang asli, berarti sel itu berisi padding
        if (num_rows_encrypt - 1) * cols + c >= original_plaintext_len:
            length -= 1
        col_lengths_in_grid[c] = length

    # Sekarang kita tahu berapa banyak karakter yang harus dibaca dari ciphertext
    # untuk mengisi setiap kolom sesuai urutan idxs_sorted_by_rank

    parts = {} # Dictionary: {indeks_kolom_asli: [daftar karakter]}
    ptr = 0 # Penunjuk posisi saat membaca ciphertext
    for col_idx_in_read_order in idxs_sorted_by_rank:
        # Ambil panjang sebenarnya dari dictionary yang sudah kita hitung
        actual_chars_in_col = col_lengths_in_grid[col_idx_in_read_order]

        # Baca sejumlah karakter tersebut dari ciphertext
        read_chars = list(ciphertext[ptr : ptr + actual_chars_in_col])
        parts[col_idx_in_read_order] = read_chars
        ptr += actual_chars_in_col

    # -- REKONSTRUKSI PLAINTEXT DARI KOLOM YANG SUDAH DIISI --
    # Buat grid kosong untuk hasil dekripsi
    decrypted_grid = [['\0'] * cols for _ in range(num_rows_encrypt)]

    # Isi grid kosong dengan karakter dari 'parts', kolom per kolom (sesuai urutan asli 0..cols-1)
    for col_idx in range(cols):
        chars_for_this_col = parts.get(col_idx, [])
        for r in range(len(chars_for_this_col)):
            decrypted_grid[r][col_idx] = chars_for_this_col[r]

    # Gabungkan karakter dari grid hasil dekripsi, baris per baris
    plaintext_chars = []
    for r in range(num_rows_encrypt):
        for c in range(cols):
            char = decrypted_grid[r][c]
            # Hanya tambahkan jika BUKAN padding DAN belum mencapai panjang asli (64)
            if char != '\0' and len(plaintext_chars) < original_plaintext_len:
                 plaintext_chars.append(char)

    plain = ''.join(plaintext_chars)

    # Validasi Akhir (Sangat Penting)
    if len(plain) != original_plaintext_len:
         # Jika logika di atas benar, ini seharusnya tidak pernah terjadi
         # Tapi jika terjadi, ini menandakan keyword salah atau ciphertext korup
         raise ValueError(f"Dekripsi Myszkowski gagal: Panjang hasil ({len(plain)}) tidak sama dengan panjang asli ({original_plaintext_len}). Keyword kemungkinan salah atau file rusak.")

    return plain # Kembalikan hex string hasil dekripsi

# ---------- Fungsi Enkripsi & Dekripsi Hybrid (Menggunakan fungsi Myszkowski di atas) ----------
def encrypt_file_hybrid(in_path: str, out_path: str, keyword_for_transpose: str):
    """Enkripsi file besar secara chunked dengan AES-GCM dan Myszkowski."""
    # 1. Buat Kunci AES & Nonce secara acak
    aes_key = get_random_bytes(32) # AES-256 (32 byte)
    aes_nonce = get_random_bytes(12) # GCM standard nonce size (12 byte)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)

    # 2. Enkripsi Kunci AES dengan Myszkowski
    key_hex = aes_key.hex() # Konversi kunci biner 32-byte ke hex string (64 char)
    key_cipher_text = myszkowski_encrypt(key_hex, keyword_for_transpose) # Transposisi hex string
    key_cipher_bytes = key_cipher_text.encode('utf-8') # Encode hasil transposisi ke bytes UTF-8
    enc_key_len = len(key_cipher_bytes)

    # 3. Proses Enkripsi File
    total = os.path.getsize(in_path)
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        # Tulis Header File (Struktur Biner)
        fout.write(b'HYBR')                            # Magic number (4 byte)
        fout.write(bytes([1]))                         # Versi (1 byte)
        fout.write(enc_key_len.to_bytes(2, 'big'))     # Panjang Kunci Terenkripsi (2 byte, big-endian)
        fout.write(key_cipher_bytes)                   # Kunci Terenkripsi (N byte)
        fout.write(len(aes_nonce).to_bytes(1, 'big'))  # Panjang Nonce (1 byte)
        fout.write(aes_nonce)                          # Nonce (12 byte)

        # Enkripsi Konten File per Chunk (64KB)
        while True:
            chunk = fin.read(CHUNK)
            if not chunk: # Jika sudah akhir file
                break
            encrypted_chunk = cipher.encrypt(chunk)
            fout.write(encrypted_chunk)

        # Tulis GCM Authentication Tag di akhir file setelah semua data
        tag = cipher.digest() # Ambil tag setelah semua enkripsi
        fout.write(tag) # Tag (16 byte)

def decrypt_file_hybrid(in_path: str, out_path: str, keyword_for_transpose: str):
    """Dekripsi file besar secara chunked, dengan penanganan error dan debugging."""
    total = os.path.getsize(in_path)
    with open(in_path, 'rb') as fin:
        # 1. Baca dan Validasi Header
        magic = fin.read(4)
        if magic != b'HYBR':
            raise ValueError("File bukan hasil enkripsi hybrid (magic mismatch)")

        _ = fin.read(1)  # Baca byte versi (saat ini versi 1)
        enc_key_len = int.from_bytes(fin.read(2), 'big')
        key_cipher_bytes = fin.read(enc_key_len)
        try:
            key_cipher_text = key_cipher_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("File korup (bagian kunci terenkripsi tidak valid UTF-8)")

        # 2. Dekripsi Kunci AES dengan Myszkowski
        try:
             key_hex = myszkowski_decrypt(key_cipher_text, keyword_for_transpose)
        except ValueError as e:
             # Menangkap error dari validasi panjang di myszkowski_decrypt
             raise ValueError(f"Gagal mendekripsi kunci: {e}")


        # ---> BLOK DEBUGGING (Memeriksa hasil Myszkowski Decrypt) <---
        # Menampilkan output langsung di UI Streamlit
        st.write(f"DEBUG: Hasil Myszkowski Decrypt: '{key_hex}' (Panjang: {len(key_hex)})")
        if not re.fullmatch(r'[0-9a-f]{64}', key_hex):
             st.warning("!!! DEBUG: WARNING! Hasil Myszkowski Decrypt BUKAN hex string 64 karakter yang valid!")
        else:
             st.info("--- DEBUG: Hasil Myszkowski Decrypt TERLIHAT valid (hex 64 char).")
        # ---> AKHIR BLOK DEBUGGING <---

        try:
            # Konversi hex string kembali ke kunci AES biner
            aes_key = bytes.fromhex(key_hex)
            if len(aes_key) != 32: # Validasi tambahan untuk AES-256
                 raise ValueError(f"Panjang kunci AES setelah dekripsi ({len(aes_key)}) tidak 32 byte.")
        except ValueError as e:
            # Gagal jika key_hex bukan hex string valid atau panjang salah
            raise ValueError(f"Keyword Myszkowski salah atau file korup ({e})")

        # Lanjutkan membaca sisa header
        nonce_len = int.from_bytes(fin.read(1), 'big')
        nonce = fin.read(nonce_len)
        if len(nonce) != 12: # Validasi panjang nonce GCM
            raise ValueError(f"Panjang nonce ({len(nonce)}) tidak 12 byte.")

        # 3. Siapkan Cipher AES-GCM untuk dekripsi
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

        # Hitung ukuran ciphertext sebenarnya (Total - Header - Tag)
        header_size = 4 + 1 + 2 + enc_key_len + 1 + nonce_len
        ciphertext_size = total - header_size - AES_TAG_LEN # Kurangi ukuran tag
        if ciphertext_size < 0:
            raise ValueError("File korup (terlalu pendek untuk berisi data dan tag)")

        # Path untuk file output sementara (untuk keamanan jika verifikasi gagal)
        temp_out_path = out_path + ".tmp_decrypt"

        try:
            # 4. Dekripsi Konten File per Chunk ke file sementara
            with open(temp_out_path, 'wb') as fout:
                bytes_read = 0
                while bytes_read < ciphertext_size:
                    read_size = min(CHUNK, ciphertext_size - bytes_read)
                    chunk = fin.read(read_size)
                    if not chunk and bytes_read < ciphertext_size:
                        # File berakhir sebelum waktunya
                        raise ValueError("File berakhir secara tak terduga saat membaca ciphertext")
                    if not chunk:
                        break # Akhir ciphertext
                    decrypted_chunk = cipher.decrypt(chunk)
                    fout.write(decrypted_chunk)
                    bytes_read += len(chunk)

            # 5. Baca GCM Tag dari akhir file input
            tag = fin.read(AES_TAG_LEN)
            if len(tag) != AES_TAG_LEN:
                raise ValueError("Tag GCM tidak lengkap atau file rusak")

            # 6. Verifikasi Tag (PENTING!)
            # Ini akan melempar ValueError jika tag tidak cocok
            cipher.verify(tag)

            # 7. Jika verifikasi berhasil, rename file sementara menjadi file output akhir
            if os.path.exists(out_path): # Hapus file output lama jika ada
                 os.remove(out_path)
            os.rename(temp_out_path, out_path)

        except ValueError as e:
            # Jika cipher.verify() gagal atau error lain terjadi, hapus file sementara
            if os.path.exists(temp_out_path):
                os.remove(temp_out_path)
            # Re-raise error, tambahkan konteks jika dari verify
            if "MAC check failed" in str(e):
                 raise ValueError(f"Dekripsi Gagal (Keyword salah atau file telah dimodifikasi): Integritas data terganggu.")
            else:
                 raise e # Re-raise error lain (misal, file korup, panjang salah)
        except Exception as e:
            # Tangkap error tak terduga lainnya dan bersihkan
            if os.path.exists(temp_out_path):
                os.remove(temp_out_path)
            raise e # Re-raise error