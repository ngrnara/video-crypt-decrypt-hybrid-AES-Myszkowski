# streamlit_app.py — versi final stabil untuk Streamlit Cloud
import streamlit as st
import os
import tempfile
import time
from crypto_hybrid import encrypt_file_hybrid, decrypt_file_hybrid

# ---------- Konfigurasi dasar ----------
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

💡 File apa pun dapat dienkripsi (.mp4, .pdf, .jpg, .docx, dll)
""")

# ---------- Simpan keyword di session agar tidak hilang ----------
if "keyword" not in st.session_state:
    st.session_state.keyword = ""

mode = st.radio("Pilih Mode:", ["🔒 Enkripsi", "🔓 Dekripsi"], horizontal=True)
file = st.file_uploader("Pilih file untuk diproses", type=None)

# ---------- Input keyword dengan indikator status ----------
keyword_input = st.text_input(
    "Masukkan Keyword Myszkowski",
    value=st.session_state.keyword,
    type="password",
    help="Gunakan keyword yang sama untuk enkripsi dan dekripsi."
)
st.session_state.keyword = keyword_input.strip()

if st.session_state.keyword:
    st.success(f"🔑 Keyword tersimpan di sesi (panjang: {len(st.session_state.keyword)} karakter)")
else:
    st.warning("⚠️ Keyword belum dimasukkan atau sudah dihapus.")

# ---------- Proses utama ----------
if file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file.getbuffer())
        tmp_path = tmp.name

    file_size = os.path.getsize(tmp_path) / (1024 * 1024)
    st.info(f"📦 File: **{file.name}** — Ukuran: {file_size:.2f} MB")

    if mode.startswith("🔒"):
        out_name = st.text_input("Nama file output:", value=file.name + ".hybr")
    else:
        guess = file.name.replace(".hybr", "")
        if guess == file.name:
            guess += ".decrypted"
        out_name = st.text_input("Nama file output:", value=guess)

    if st.button(f"▶️ Mulai {mode.replace('🔒','Enkripsi').replace('🔓','Dekripsi')}"):
        keyword = st.session_state.keyword
        if not keyword:
            st.error("❌ Harap masukkan keyword Myszkowski.")
        else:
            t0 = time.time()
            progress = st.progress(0)
            try:
                if mode.startswith("🔒"):
                    with st.spinner("🔐 Sedang mengenkripsi..."):
                        encrypt_file_hybrid(tmp_path, out_name, keyword)
                        for i in range(100):
                            time.sleep(0.01)
                            progress.progress(i + 1)
                    elapsed = time.time() - t0
                    st.success(f"✅ Enkripsi selesai dalam {elapsed:.2f} detik")
                    with open(out_name, "rb") as f:
                        st.download_button(
                            "⬇️ Download File Terenkripsi (.hybr)",
                            f, file_name=os.path.basename(out_name)
                        )
                else:
                    with st.spinner("🔓 Sedang mendekripsi..."):
                        decrypt_file_hybrid(tmp_path, out_name, keyword)
                        for i in range(100):
                            time.sleep(0.01)
                            progress.progress(i + 1)
                    elapsed = time.time() - t0
                    st.success(f"✅ Dekripsi selesai dalam {elapsed:.2f} detik")
                    with open(out_name, "rb") as f:
                        st.download_button(
                            "⬇️ Download File Asli",
                            f, file_name=os.path.basename(out_name)
                        )

            except ValueError as e:
                msg = str(e).lower()
                if "key hex tidak valid" in msg:
                    st.error("❌ Keyword Myszkowski salah atau file .hybr korup.\nPastikan keyword sama persis.")
                elif "mac check failed" in msg:
                    st.error("⚠️ File terenkripsi tidak valid atau telah dimodifikasi (Tag GCM gagal).")
                elif "not a hybrid" in msg:
                    st.error("⚠️ File bukan hasil enkripsi (.hybr) yang valid.")
                else:
                    st.error(f"❌ Terjadi kesalahan: {e}")
            except Exception as e:
                st.error(f"❌ Error tak terduga: {e}")
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

# ---------- Reset Session ----------
st.divider()
if st.button("🧹 Reset Keyword Session"):
    st.session_state.keyword = ""
    st.success("✅ Keyword telah dihapus dari sesi aktif.")
