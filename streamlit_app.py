# streamlit_app.py (versi update dengan progress bar & error handling)
import streamlit as st
import os
import tempfile
import time
from crypto_hybrid import encrypt_file_hybrid, decrypt_file_hybrid

# 🔧 Konfigurasi halaman
st.set_page_config(
    page_title="VideoHybrid — AES + Myszkowski",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ VideoHybrid — Enkripsi & Dekripsi File (AES-GCM + Myszkowski)")

st.markdown("""
Aplikasi ini menggunakan skema **super-enkripsi hybrid**:
- 🔐 **AES-256-GCM** untuk konten file (video, dokumen, dll)
- 🔁 **Myszkowski Transposition Cipher** untuk mengenkripsi kunci AES

💡 File apa pun dapat dienkripsi (.mp4, .pdf, .jpg, dll)
""")

mode = st.radio("Pilih Mode:", ["🔒 Enkripsi", "🔓 Dekripsi"], horizontal=True)
file = st.file_uploader("Pilih file untuk diproses", type=None)
keyword = st.text_input("Masukkan Keyword kunci", type="password")

if file:
    # Simpan file upload ke temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file.getbuffer())
        tmp_path = tmp.name

    file_size = os.path.getsize(tmp_path) / (1024 * 1024)
    st.info(f"📦 File: **{file.name}** — Ukuran: {file_size:.2f} MB")

    # Tentukan nama file output default
    if mode.startswith("🔒"):
        out_name = st.text_input("Nama file output:", value=file.name + ".hybr")
    else:
        guess = file.name.replace(".hybr", "")
        if guess == file.name:
            guess += ".decrypted"
        out_name = st.text_input("Nama file output:", value=guess)

    if st.button(f"▶️ Mulai {mode.replace('🔒','Enkripsi').replace('🔓','Dekripsi')}"):
        if not keyword:
            st.error("❌ Harap masukkan keyword Myszkowski.")
        else:
            st.write(f"DEBUG: Keyword yang akan digunakan: '{keyword}' (Panjang: {len(keyword)})")
            t0 = time.time()
            progress = st.progress(0)
            try:
                if mode.startswith("🔒"):
                    # Enkripsi
                    with st.spinner("Sedang mengenkripsi... Mohon tunggu."):
                        encrypt_file_hybrid(tmp_path, out_name, keyword)
                        for i in range(100):
                            time.sleep(0.01)
                            progress.progress(i + 1)

                    elapsed = time.time() - t0
                    st.success(f"✅ Enkripsi Berhasil dalam {elapsed:.2f} detik")
                    with open(out_name, "rb") as f:
                        st.download_button("⬇️ Download File Terenkripsi (.hybr)", f, file_name=os.path.basename(out_name))

                else:
                    # Dekripsi
                    with st.spinner("Sedang mendekripsi... Mohon tunggu."):
                        decrypt_file_hybrid(tmp_path, out_name, keyword)
                        for i in range(100):
                            time.sleep(0.01)
                            progress.progress(i + 1)

                    elapsed = time.time() - t0
                    st.success(f"✅ Dekripsi Berhasil dalam {elapsed:.2f} detik")
                    with open(out_name, "rb") as f:
                        st.download_button("⬇️ Download File Asli", f, file_name=os.path.basename(out_name))

            except ValueError as e:
                msg = str(e)
                if "key hex tidak valid" in msg.lower():
                    st.error("❌ Keyword Myszkowski salah atau file .hybr korup.\n\nPastikan keyword sama persis seperti saat enkripsi.")
                elif "mac check failed" in msg.lower():
                    st.error("⚠️ File terenkripsi tidak valid atau telah dimodifikasi (Tag GCM gagal).")
                elif "not a hybrid" in msg.lower():
                    st.error("⚠️ File yang diunggah bukan file terenkripsi (.hybr) yang valid.")
                else:
                    st.error(f"❌ Terjadi kesalahan: {msg}")

            except Exception as e:
                st.error(f"❌ Error tak terduga: {e}")

            finally:
                # Bersihkan file sementara
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
