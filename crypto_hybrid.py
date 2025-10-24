# crypto_hybrid.py
import os
import streamlit as st # <-- Import Streamlit untuk debugging
import re              # <-- Import Regex untuk debugging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------- Konstanta ----------
CHUNK = 64 * 1024  # 64KB
AES_TAG_LEN = 16   # Ukuran tag otentikasi GCM

# ---------- Fungsi Helper Myszkowski ----------
def _keyword_order(keyword: str):
    """
    Menghasilkan urutan peringkat untuk Myszkowski.
    Huruf yang sama memiliki peringkat yang sama, berdasarkan urutan alfabet.
    Contoh: "BALLOON" -> [2, 1, 3, 3, 4, 4, 5] (A=1, B=2, L=3, N=4, O=5)
    """
    chars = list(keyword)
    unique_sorted = sorted(set(chars))
    rank_map = {c: i + 1 for i, c in enumerate(unique_sorted)}
    return [rank_map[c] for c in chars]

# ---------- Fungsi Myszkowski Cipher (Harus didefinisikan SEBELUM digunakan) ----------
def myszkowski_encrypt(plaintext: str, keyword: str) -> str:
    """
    Enkripsi string menggunakan transposisi Myszkowski.
    plaintext: string untuk ditransposisi (hex string dari kunci AES).
    keyword: keyword string.
    returns: ciphertext string hasil transposisi.
    """
    if not keyword:
        raise ValueError("Keyword diperlukan untuk Myszkowski")

    cols = len(keyword)
    # Buat baris, pad dengan null char '\0' jika perlu
    rows = []
    for i in range(0, len(plaintext), cols):
        rows.append(list(plaintext[i:i + cols].ljust(cols, '\0')))

    ranks = _keyword_order(keyword)

    # Dapatkan indeks kolom, urutkan berdasarkan (peringkat, lalu indeks asli)
    idxs = list(range(cols))
    idxs_sorted = sorted(idxs, key=lambda i: (ranks[i], i))

    result_chars = []
    for col in idxs_sorted:
        for r in range(len(rows)):
            ch = rows[r][col]
            if ch != '\0': # Jangan tambahkan padding null ke hasil
                result_chars.append(ch)

    return ''.join(result_chars)

def myszkowski_decrypt(ciphertext: str, keyword: str) -> str:
    """
    Mendekripsi ciphertext Myszkowski.
    """
    if not keyword:
        raise ValueError("Keyword diperlukan untuk Myszkowski")

    cols = len(keyword)
    ranks = _keyword_order(keyword)
    idxs = list(range(cols))
    idxs_sorted = sorted(idxs, key=lambda i: (ranks[i], i))

    # Hitung panjang setiap kolom dalam urutan baca (idxs_sorted)
    base_len = len(ciphertext) // cols
    remainder = len(ciphertext) % cols

    col_lens_sorted = []
    for i_pos in range(len(idxs_sorted)):
        # Kolom pertama dalam urutan baca mendapat sisa karakter
        if i_pos < remainder:
            col_lens_sorted.append(base_len + 1)
        else:
            col_lens_sorted.append(base_len)

    # Pisahkan ciphertext berdasarkan panjang kolom yang dihitung
    parts = {}
    ptr = 0
    for idx_sorted_pos, col_idx in enumerate(idxs_sorted):
        l = col_lens_sorted[idx_sorted_pos]
        parts[col_idx] = list(ciphertext[ptr:ptr + l])
        ptr += l

    # Rekonstruksi baris grid
    rows = []
    # Tentukan jumlah baris maksimum berdasarkan kolom terpanjang
    max_r = max((len(parts[c]) for c in range(cols))) if parts else 0

    for r in range(max_r):
        row_chars = []
        for c in range(cols): # Baca kolom sesuai urutan asli 0, 1, 2, ...
            col_list = parts.get(c, [])
            if r < len(col_list):
                row_chars.append(col_list[r])
            else:
                # Jika kolom lebih pendek, ini adalah posisi padding
                row_chars.append('\0')
        rows.append(row_chars)

    # Gabungkan semua karakter dari grid dan hapus padding null di akhir
    plain = ''.join(''.join(row) for row in rows).rstrip('\0')
    return plain

# ---------- Fungsi Enkripsi & Dekripsi Hybrid (Menggunakan fungsi Myszkowski di atas) ----------
def encrypt_file_hybrid(in_path: str, out_path: str, keyword_for_transpose: str):
    """Enkripsi file besar secara chunked dengan AES-GCM dan Myszkowski."""
    # 1. Buat Kunci AES & Nonce
    aes_key = get_random_bytes(32) # AES-256
    aes_nonce = get_random_bytes(12) # GCM standard nonce size
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)

    # 2. Enkripsi Kunci AES dengan Myszkowski
    key_hex = aes_key.hex() # Konversi kunci biner ke hex string (64 char)
    key_cipher_text = myszkowski_encrypt(key_hex, keyword_for_transpose) # Transposisi hex string
    key_cipher_bytes = key_cipher_text.encode('utf-8') # Encode hasil transposisi ke bytes
    enc_key_len = len(key_cipher_bytes)

    # 3. Proses Enkripsi File
    total = os.path.getsize(in_path)
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        # Tulis Header File
        fout.write(b'HYBR')                            # Magic number (4 byte)
        fout.write(bytes([1]))                         # Versi (1 byte)
        fout.write(enc_key_len.to_bytes(2, 'big'))     # Panjang Kunci Terenkripsi (2 byte)
        fout.write(key_cipher_bytes)                   # Kunci Terenkripsi (N byte)
        fout.write(len(aes_nonce).to_bytes(1, 'big'))  # Panjang Nonce (1 byte)
        fout.write(aes_nonce)                          # Nonce (12 byte)

        # Enkripsi Konten File per Chunk
        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            encrypted_chunk = cipher.encrypt(chunk)
            fout.write(encrypted_chunk)

        # Tulis GCM Authentication Tag di akhir file
        tag = cipher.digest()
        fout.write(tag) # Tag (16 byte)

def decrypt_file_hybrid(in_path: str, out_path: str, keyword_for_transpose: str):
    """Dekripsi file besar secara chunked."""
    total = os.path.getsize(in_path)
    with open(in_path, 'rb') as fin:
        # 1. Baca Header
        magic = fin.read(4)
        if magic != b'HYBR':
            raise ValueError("File bukan hasil enkripsi hybrid (magic mismatch)")

        _ = fin.read(1)  # Baca byte versi (saat ini diabaikan)
        enc_key_len = int.from_bytes(fin.read(2), 'big')
        key_cipher_bytes = fin.read(enc_key_len)
        key_cipher_text = key_cipher_bytes.decode('utf-8')

        # 2. Dekripsi Kunci AES dengan Myszkowski
        key_hex = myszkowski_decrypt(key_cipher_text, keyword_for_transpose)

        # ---> BLOK DEBUGGING (Memeriksa hasil Myszkowski Decrypt) <---
        st.write(f"DEBUG: Hasil Myszkowski Decrypt: '{key_hex}' (Panjang: {len(key_hex)})")
        if not re.fullmatch(r'[0-9a-f]{64}', key_hex):
             st.warning("!!! DEBUG: WARNING! Hasil Myszkowski Decrypt BUKAN hex string 64 karakter yang valid!")
        else:
             st.info("--- DEBUG: Hasil Myszkowski Decrypt TERLIHAT valid (hex 64 char).")
        # ---> AKHIR BLOK DEBUGGING <---

        try:
            # Konversi hex string kembali ke kunci AES biner
            aes_key = bytes.fromhex(key_hex)
        except ValueError:
            # Gagal jika key_hex bukan hex string valid
            raise ValueError("Keyword Myszkowski salah atau file korup (key hex tidak valid)")

        # Lanjutkan membaca header
        nonce_len = int.from_bytes(fin.read(1), 'big')
        nonce = fin.read(nonce_len)

        # 3. Siapkan Cipher AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

        # Hitung ukuran ciphertext sebenarnya
        header_size = 4 + 1 + 2 + enc_key_len + 1 + nonce_len
        ciphertext_size = total - header_size - AES_TAG_LEN # Kurangi ukuran tag
        if ciphertext_size < 0:
            raise ValueError("File korup (terlalu pendek untuk berisi data dan tag)")

        # Path untuk file output sementara
        temp_out_path = out_path + ".tmp_decrypt"

        try:
            # 4. Dekripsi Konten File per Chunk ke file sementara
            with open(temp_out_path, 'wb') as fout:
                bytes_read = 0
                while bytes_read < ciphertext_size:
                    read_size = min(CHUNK, ciphertext_size - bytes_read)
                    chunk = fin.read(read_size)
                    if not chunk:
                        # Ini seharusnya tidak terjadi jika ciphertext_size benar
                        raise ValueError("File berakhir secara tak terduga saat membaca ciphertext")
                    decrypted_chunk = cipher.decrypt(chunk)
                    fout.write(decrypted_chunk)
                    bytes_read += len(chunk)

            # 5. Baca GCM Tag dari akhir file input
            tag = fin.read(AES_TAG_LEN)
            if len(tag) != AES_TAG_LEN:
                raise ValueError("Tag GCM tidak lengkap atau file rusak")

            # 6. Verifikasi Tag (Penting!)
            # Ini akan melempar ValueError jika tag tidak cocok (kunci salah/file diubah)
            cipher.verify(tag)

            # 7. Jika verifikasi berhasil, rename file sementara menjadi file output akhir
            os.rename(temp_out_path, out_path)

        except ValueError as e:
            # Jika cipher.verify() gagal atau error lain terjadi, hapus file sementara
            if os.path.exists(temp_out_path):
                os.remove(temp_out_path)
            # Re-raise error, tambahkan konteks jika dari verify
            if "MAC check failed" in str(e):
                 raise ValueError(f"Dekripsi Gagal (Keyword salah atau file telah dimodifikasi): {e}")
            else:
                 raise e # Re-raise error lain (misal, file korup)
        except Exception as e:
            # Tangkap error tak terduga lainnya dan bersihkan
            if os.path.exists(temp_out_path):
                os.remove(temp_out_path)
            raise e # Re-raise error