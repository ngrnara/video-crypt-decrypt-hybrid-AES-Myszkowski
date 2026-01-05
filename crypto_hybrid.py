# crypto_hybrid.py (Versi Final - Fixed "asd/asf" Bug)
import os
import streamlit as st
import re
import hashlib  # <--- [BARU] Import library untuk hashing
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------- Konstanta ----------
CHUNK = 64 * 1024  # 64KB
AES_TAG_LEN = 16   # GCM Tag

# ---------- Fungsi Helper Myszkowski ----------
def _keyword_order(keyword: str):
    """
    Menghasilkan urutan peringkat numerik.
    """
    chars = list(keyword)
    unique_sorted = sorted(set(chars))
    rank_map = {c: i + 1 for i, c in enumerate(unique_sorted)}
    return [rank_map[c] for c in chars]

# ---------- Fungsi Myszkowski Cipher ----------
def myszkowski_encrypt(plaintext: str, keyword: str) -> str:
    if not keyword:
        raise ValueError("Keyword diperlukan")

    cols = len(keyword)
    rows = []
    for i in range(0, len(plaintext), cols):
        rows.append(list(plaintext[i:i + cols].ljust(cols, '\0')))

    ranks = _keyword_order(keyword)
    idxs = list(range(cols))
    idxs_sorted = sorted(idxs, key=lambda i: (ranks[i], i))

    result_chars = []
    for col in idxs_sorted:
        for r in range(len(rows)):
            ch = rows[r][col]
            if ch != '\0':
                result_chars.append(ch)

    return ''.join(result_chars)

def myszkowski_decrypt(ciphertext: str, keyword: str) -> str:
    if not keyword:
        raise ValueError("Keyword diperlukan")

    cols = len(keyword)
    original_plaintext_len = 64 

    num_rows_encrypt = (original_plaintext_len + cols - 1) // cols
    
    # Rekonstruksi grid
    ranks = _keyword_order(keyword)
    idxs = list(range(cols))
    idxs_sorted_by_rank = sorted(idxs, key=lambda i: (ranks[i], i))

    col_lengths_in_grid = {}
    for c in range(cols):
        length = num_rows_encrypt
        if (num_rows_encrypt - 1) * cols + c >= original_plaintext_len:
            length -= 1
        col_lengths_in_grid[c] = length

    parts = {}
    ptr = 0
    for col_idx_in_read_order in idxs_sorted_by_rank:
        actual_chars_in_col = col_lengths_in_grid[col_idx_in_read_order]
        read_chars = list(ciphertext[ptr : ptr + actual_chars_in_col])
        parts[col_idx_in_read_order] = read_chars
        ptr += actual_chars_in_col

    decrypted_grid = [['\0'] * cols for _ in range(num_rows_encrypt)]
    for col_idx in range(cols):
        chars_for_this_col = parts.get(col_idx, [])
        for r in range(len(chars_for_this_col)):
            decrypted_grid[r][col_idx] = chars_for_this_col[r]

    plaintext_chars = []
    for r in range(num_rows_encrypt):
        for c in range(cols):
            char = decrypted_grid[r][c]
            if char != '\0' and len(plaintext_chars) < original_plaintext_len:
                 plaintext_chars.append(char)

    plain = ''.join(plaintext_chars)

    if len(plain) != original_plaintext_len:
         raise ValueError(f"Dekripsi gagal. Panjang hasil ({len(plain)}) tidak valid.")

    return plain

# ---------- Fungsi Utama Hybrid (Modified) ----------
def encrypt_file_hybrid(in_path: str, out_path: str, keyword_for_transpose: str):
    # [PERBAIKAN] Hash keyword user agar "asd" dan "asf" jadi string yang beda total
    secure_keyword = hashlib.sha256(keyword_for_transpose.encode()).hexdigest()
    
    # 1. Buat Kunci AES & Nonce
    aes_key = get_random_bytes(32)
    aes_nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)

    # 2. Enkripsi Kunci AES dengan Myszkowski (Gunakan secure_keyword)
    key_hex = aes_key.hex()
    key_cipher_text = myszkowski_encrypt(key_hex, secure_keyword) # <--- Pakai hash
    key_cipher_bytes = key_cipher_text.encode('utf-8')
    enc_key_len = len(key_cipher_bytes)

    # 3. Proses Enkripsi File
    total = os.path.getsize(in_path)
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        fout.write(b'HYBR')
        fout.write(bytes([1]))
        fout.write(enc_key_len.to_bytes(2, 'big'))
        fout.write(key_cipher_bytes)
        fout.write(len(aes_nonce).to_bytes(1, 'big'))
        fout.write(aes_nonce)

        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            encrypted_chunk = cipher.encrypt(chunk)
            fout.write(encrypted_chunk)

        tag = cipher.digest()
        fout.write(tag)

def decrypt_file_hybrid(in_path: str, out_path: str, keyword_for_transpose: str):
    # [PERBAIKAN] Hash keyword user agar konsisten dengan saat enkripsi
    secure_keyword = hashlib.sha256(keyword_for_transpose.encode()).hexdigest()

    total = os.path.getsize(in_path)
    with open(in_path, 'rb') as fin:
        # 1. Baca Header
        magic = fin.read(4)
        if magic != b'HYBR':
            raise ValueError("Bukan file HYBR")

        _ = fin.read(1)
        enc_key_len = int.from_bytes(fin.read(2), 'big')
        key_cipher_bytes = fin.read(enc_key_len)
        try:
            key_cipher_text = key_cipher_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("File korup (UTF-8 error)")

        # 2. Dekripsi Myszkowski (Gunakan secure_keyword)
        try:
             key_hex = myszkowski_decrypt(key_cipher_text, secure_keyword) # <--- Pakai hash
        except ValueError as e:
             raise ValueError(f"Gagal dekripsi kunci: {e}")

        # Debugging
        st.write(f"DEBUG: Myszkowski Key Result (First 10 chars): {key_hex[:10]}...")

        try:
            aes_key = bytes.fromhex(key_hex)
            if len(aes_key) != 32:
                 raise ValueError("Panjang kunci salah")
        except ValueError:
            raise ValueError("Keyword salah (Hash tidak cocok)")

        nonce_len = int.from_bytes(fin.read(1), 'big')
        nonce = fin.read(nonce_len)
        
        # 3. Setup AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        
        header_size = 4 + 1 + 2 + enc_key_len + 1 + nonce_len
        ciphertext_size = total - header_size - AES_TAG_LEN
        
        temp_out_path = out_path + ".tmp_decrypt"

        try:
            with open(temp_out_path, 'wb') as fout:
                bytes_read = 0
                while bytes_read < ciphertext_size:
                    read_size = min(CHUNK, ciphertext_size - bytes_read)
                    chunk = fin.read(read_size)
                    if not chunk: break
                    decrypted_chunk = cipher.decrypt(chunk)
                    fout.write(decrypted_chunk)
                    bytes_read += len(chunk)

            tag = fin.read(AES_TAG_LEN)
            
            # 4. Verifikasi Tag (GCM Check)
            cipher.verify(tag)

            if os.path.exists(out_path):
                 os.remove(out_path)
            os.rename(temp_out_path, out_path)

        except Exception as e:
            if os.path.exists(temp_out_path):
                os.remove(temp_out_path)
            if "MAC check failed" in str(e):
                 raise ValueError("Password Salah! (MAC Check Failed)")
            else:
                 raise e