# streamlit_app.py
import streamlit as st
import os
import tempfile
import time
from crypto_hybrid import encrypt_file_hybrid, decrypt_file_hybrid, myszkowski_encrypt, myszkowski_decrypt

st.set_page_config(page_title="VideoHybrid (AES + Myszkowski)", layout="centered")
st.title("VideoHybrid — Enkripsi Video (AES-GCM) + Myszkowski (Transposisi)")

st.markdown("""
**Penjelasan singkat:** file video dienkripsi dengan AES-GCM (random AES key). Kunci AES dienkripsi ulang menggunakan **Myszkowski transposition** dengan keyword yang Anda masukkan. Saat dekripsi, keyword yang sama diperlukan untuk memulihkan kunci AES lalu mendekripsi file.
""")

mode = st.radio("Pilih Mode:", ["Enkripsi", "Dekripsi"], horizontal=True)
uploaded = st.file_uploader("Pilih file (video, pdf, dll.)", type=None) # type=None agar bisa semua file
keyword = st.text_input("Keyword Myszkowski (Masukkan password Anda)", type="password")

if uploaded:
    # Buat file temporary untuk menampung upload
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded.getbuffer())
        tmp_path = tmp.name
        
    st.info(f"Nama file: {uploaded.name} | Ukuran: {os.path.getsize(tmp_path) / 1024 / 1024:.2f} MB")
    
    out_default = ""
    if mode == "Enkripsi":
        out_default = uploaded.name + ".hybr"
    else:
        # Coba tebak nama asli
        out_default = uploaded.name.replace(".hybr", "")
        if out_default == uploaded.name:
             out_default = uploaded.name + ".decrypted"

    out_name = st.text_input("Nama file output:", value=out_default)
    
    if st.button(f"Mulai {mode}"):
        if not keyword:
            st.error("Masukkan keyword (password) untuk Myszkowski")
        elif not out_name:
            st.error("Masukkan nama file output")
        else:
            t0 = time.time()
            try:
                if mode == "Enkripsi":
                    with st.spinner("Sedang mengenkripsi... Ini mungkin butuh waktu untuk file besar."):
                        encrypt_file_hybrid(tmp_path, out_name, keyword)
                    
                    elapsed = time.time() - t0
                    st.success(f"Enkripsi Berhasil -> {out_name} (Waktu: {elapsed:.2f} detik)")
                    
                    with open(out_name, "rb") as f:
                        st.download_button("Download File Terenkripsi (.hybr)", f, file_name=os.path.basename(out_name))
                
                else: # Mode Dekripsi
                    with st.spinner("Sedang mendekripsi... Ini mungkin butuh waktu untuk file besar."):
                        decrypt_file_hybrid(tmp_path, out_name, keyword)
                    
                    elapsed = time.time() - t0
                    st.success(f"Dekripsi Berhasil -> {out_name} (Waktu: {elapsed:.2f} detik)")
                    
                    with open(out_name, "rb") as f:
                        st.download_button("Download File Asli", f, file_name=os.path.basename(out_name))
                        
            except Exception as e:
                st.error(f"Proses Gagal: {e}")
            finally:
                # Selalu hapus file temporary
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass