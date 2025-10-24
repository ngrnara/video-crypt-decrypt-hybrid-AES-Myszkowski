# crypto_hybrid.py
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CHUNK = 64 * 1024  # 64KB
AES_TAG_LEN = 16

# ---------------- Myszkowski transposition (encrypt & decrypt)
# Implementation works on arbitrary text (we'll pass hex string of AES key)

def _keyword_order(keyword: str):
    """
    Menghasilkan urutan peringkat untuk Myszkowski.
    Huruf yang sama memiliki peringkat yang sama, berdasarkan urutan alfabet.
    Contoh: "BALLOON" -> [2, 1, 3, 3, 4, 4, 5] (A=1, B=2, L=3, N=4, O=5)
    """
    chars = list(keyword)
    unique_sorted = sorted(set(chars))
    rank_map = {c: i+1 for i, c in enumerate(unique_sorted)}
    return [rank_map[c] for c in chars]

def myszkowski_encrypt(plaintext: str, keyword: str) -> str:
    """
    plaintext: string untuk ditransposisi (hex string dari kunci AES)
    keyword: keyword string
    returns: ciphertext string hasil transposisi
    """
    if not keyword:
        raise ValueError("Keyword diperlukan untuk Myszkowski")
    
    cols = len(keyword)
    # Buat baris, pad dengan null char '\0' jika perlu
    rows = []
    for i in range(0, len(plaintext), cols):
        rows.append(list(plaintext[i:i+cols].ljust(cols, '\0')))
        
    ranks = _keyword_order(keyword)
    
    # Dapatkan indeks kolom, urutkan berdasarkan (peringkat, lalu indeks asli)
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
        if i_pos < remainder:
            col_lens_sorted.append(base_len + 1)
        else:
            col_lens_sorted.append(base_len)
            
    # Pisahkan ciphertext berdasarkan panjang kolom
    parts = {}
    ptr = 0
    for idx_sorted_pos, col_idx in enumerate(idxs_sorted):
        l = col_lens_sorted[idx_sorted_pos]
        parts[col_idx] = list(ciphertext[ptr:ptr+l])
        ptr += l
        
    # Rekonstruksi baris
    rows = []
    max_r = max((len(parts[c]) for c in range(cols))) if parts else 0
    
    for r in range(max_r):
        row_chars = []
        for c in range(cols):
            col_list = parts.get(c, [])
            if r < len(col_list):
                row_chars.append(col_list[r])
            else:
                row_chars.append('\0') # Pad jika kolom lebih pendek
        rows.append(row_chars)
        
    # Gabungkan dan hapus padding null
    plain = ''.join(''.join(row) for row in rows).rstrip('\0')
    return plain

# ---------------- AES-GCM file encryption

def encrypt_file_hybrid(in_path: str, out_path: str, keyword_for_transpose: str):
    """
    Enkripsi file besar secara chunked.
    """
    # 1) Buat kunci AES acak (32 byte = 256-bit) dan nonce (12 byte)
    aes_key = get_random_bytes(32)
    aes_nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    
    # 2) Ubah kunci AES biner -> hex string, lalu enkripsi hex string dgn Myszkowski
    key_hex = aes_key.hex()
    key_cipher_text = myszkowski_encrypt(key_hex, keyword_for_transpose)
    key_cipher_bytes = key_cipher_text.encode('utf-8')
    enc_key_len = len(key_cipher_bytes)
    
    # 3) Tulis header file, lalu enkripsi chunked
    total = os.path.getsize(in_path)
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        # Tulis Header
        fout.write(b'HYBR')  # Magic number 4 byte
        fout.write(bytes([1]))  # Versi 1 byte
        fout.write(enc_key_len.to_bytes(2, 'big'))  # Panjang kunci terenkripsi 2 byte
        fout.write(key_cipher_bytes)               # Kunci terenkripsi N byte
        fout.write(len(aes_nonce).to_bytes(1, 'big')) # Panjang nonce 1 byte
        fout.write(aes_nonce)                      # Nonce 12 byte
        
        # Enkripsi konten
        while True:
            chunk = fin.read(CHUNK)
            if not chunk:
                break
            fout.write(cipher.encrypt(chunk))
            
        # Tulis GCM Tag di akhir
        fout.write(cipher.digest())

def decrypt_file_hybrid(in_path: str, out_path: str, keyword_for_transpose: str):
    """
    Mendekripsi file besar secara chunked (Versi Perbaikan Memori).
    """
    total = os.path.getsize(in_path)

    with open(in_path, 'rb') as fin:
        magic = fin.read(4)
        if magic != b'HYBR':
            raise ValueError("File not a hybrid-encrypted file (magic mismatch)")
        
        version = fin.read(1) # versi 1
        
        enc_key_len = int.from_bytes(fin.read(2), 'big')
        key_cipher_bytes = fin.read(enc_key_len)
        key_cipher_text = key_cipher_bytes.decode('utf-8')
        
        # 1. Pulihkan kunci AES
        key_hex = myszkowski_decrypt(key_cipher_text, keyword_for_transpose)
        try:
            aes_key = bytes.fromhex(key_hex)
        except ValueError:
            raise ValueError("Keyword Myszkowski salah atau header file korup (key hex tidak valid)")

        nonce_len = int.from_bytes(fin.read(1), 'big')
        nonce = fin.read(nonce_len)

        # 2. Siapkan cipher AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

        # 3. Dekripsi chunk-by-chunk
        header_size = 4 + 1 + 2 + enc_key_len + 1 + nonce_len
        ciphertext_size = total - header_size - AES_TAG_LEN
        
        if ciphertext_size < 0:
            raise ValueError("File korup (terlalu pendek)")

        try:
            with open(out_path, 'wb') as fout:
                bytes_read = 0
                while bytes_read < ciphertext_size:
                    read_size = min(CHUNK, ciphertext_size - bytes_read)
                    chunk = fin.read(read_size)
                    if not chunk:
                        break 
                    
                    dec_chunk = cipher.decrypt(chunk)
                    fout.write(dec_chunk)
                    bytes_read += len(chunk)

            # 4. Setelah semua ciphertext didekripsi, baca tag dan verifikasi
            tag = fin.read(AES_TAG_LEN)
            if len(tag) != AES_TAG_LEN:
                 raise ValueError(f"File korup (tag tidak lengkap, hanya {len(tag)} bytes)")
                 
            cipher.verify(tag) # Akan raise ValueError jika tag tidak cocok
            
        except ValueError as e:
            # Jika verifikasi gagal, hapus file output yang mungkin rusak
            if os.path.exists(out_path):
                os.remove(out_path)
            raise ValueError(f"Dekripsi Gagal (Keyword salah atau file telah dimodifikasi): {e}")
        except Exception as e:
            if os.path.exists(out_path):
                os.remove(out_path)
            raise e