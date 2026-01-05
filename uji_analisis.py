import os
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from crypto_hybrid import encrypt_file_hybrid 

def calculate_entropy(data):
    """Menghitung Entropi Shannon (Keacakan data). Ideal = 8.0"""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def calculate_avalanche_effect(str1, str2):
    """Menghitung persentase perbedaan bit antara dua string byte."""
    # memastikan panjang sama (potong ke panjang terpendek untuk perbandingan)
    min_len = min(len(str1), len(str2))
    diff_bits = 0
    
    for i in range(min_len):
        # XOR byte untuk cari beda, lalu hitung bit 1 (popcount)
        xor_val = str1[i] ^ str2[i]
        diff_bits += bin(xor_val).count('1')
    
    total_bits = min_len * 8
    return (diff_bits / total_bits) * 100

def run_tests():
    print("--- MULAI PENGUJIAN ANALISIS KEAMANAN ---")
    
    # 1. Siapkan File Dummp
    dummy_file = "test_analysis.txt"
    with open(dummy_file, "wb") as f:
        f.write(b"A" * 1024) # 1KB data dummy
        
    output_1 = "out_test_1.hybr"
    output_2 = "out_test_2.hybr"
    
    # --- UJI 1: ENTROPI ---
    print("\n[1] PENGUJIAN ENTROPI")
    key_normal = "rahasia1"
    encrypt_file_hybrid(dummy_file, output_1, key_normal)
    
    with open(output_1, "rb") as f:
        cipher_data = f.read()
        
    entropy_val = calculate_entropy(cipher_data)
    print(f"   > Entropi File Terenkripsi: {entropy_val:.5f}")
    if entropy_val > 7.9:
        print("   > Status: SANGAT BAIK (Mendekati 8.0)")
    else:
        print("   > Status: KURANG BAIK")

    # --- UJI 2: AVALANCHE EFFECT ---
    print("\n[2] PENGUJIAN AVALANCHE EFFECT")
    print("   Skenario: Mengubah keyword 'rahasia1' menjadi 'rahasia2' (beda 1 char)")
    
    # Enkripsi pertama (Keyword A)
    encrypt_file_hybrid(dummy_file, output_1, key_normal)
    
    # Enkripsi kedua (Keyword B - beda sedikit)
    key_changed = "rahasia2" 
    encrypt_file_hybrid(dummy_file, output_2, key_changed)
    
    # Baca kedua ciphertext
    with open(output_1, "rb") as f1, open(output_2, "rb") as f2:
        c1 = f1.read()
        c2 = f2.read()
    
    avalanche = calculate_avalanche_effect(c1, c2)
    print(f"   > Perubahan Bit (Avalanche Effect): {avalanche:.2f}%")
    if 45 <= avalanche <= 55:
        print("   > Status: IDEAL (Mendekati 50%)")
    else:
        print("   > Status: MENYIMPANG (Cek apakah IV/Nonce berubah?)")

    # Bersihkan file
    try:
        os.remove(dummy_file)
        os.remove(output_1)
        os.remove(output_2)
    except:
        pass

if __name__ == "__main__":
    run_tests()