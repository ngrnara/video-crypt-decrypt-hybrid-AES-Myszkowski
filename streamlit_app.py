# streamlit_app.py — versi final stabil + throughput
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
uploaded_file = st.file_uploader("Pilih file untuk diproses", type=None) # Ganti nama variabel 'file' jadi 'uploaded_file'

# ---------- Input keyword dengan indikator status ----------
keyword_input = st.text_input(
    "Masukkan Keyword Myszkowski",
    value=st.session_state.keyword,
    type="password",
    help="Gunakan keyword yang sama untuk enkripsi dan dekripsi."
)
# Hapus spasi di awal/akhir keyword saat disimpan
st.session_state.keyword = keyword_input.strip() 

if st.session_state.keyword:
    st.success(f"🔑 Keyword tersimpan di sesi (panjang: {len(st.session_state.keyword)} karakter)")
else:
    st.warning("⚠️ Keyword belum dimasukkan atau sudah dihapus.")

# ---------- Proses utama ----------
if uploaded_file: # Gunakan nama variabel baru
    # Simpan file upload ke temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.getbuffer()) # Gunakan nama variabel baru
        tmp_path = tmp.name

    # Ukuran file asli (untuk perhitungan throughput)
    original_file_size_bytes = os.path.getsize(tmp_path)
    original_file_size_mb = original_file_size_bytes / (1024 * 1024)
    st.info(f"📦 File: **{uploaded_file.name}** — Ukuran: {original_file_size_mb:.2f} MB") # Gunakan nama variabel baru

    # Tentukan nama file output default
    if mode.startswith("🔒"):
        out_name = st.text_input("Nama file output:", value=uploaded_file.name + ".hybr") # Gunakan nama variabel baru
    else:
        guess = uploaded_file.name.replace(".hybr", "") # Gunakan nama variabel baru
        if guess == uploaded_file.name: # Gunakan nama variabel baru
            guess += ".decrypted"
        out_name = st.text_input("Nama file output:", value=guess)

    if st.button(f"▶️ Mulai {mode.replace('🔒','Enkripsi').replace('🔓','Dekripsi')}"):
        keyword = st.session_state.keyword
        if not keyword:
            st.error("❌ Harap masukkan keyword Myszkowski.")
        elif not out_name:
             st.error("❌ Harap masukkan nama file output.")
        else:
            t0 = time.time()
            progress = st.progress(0)
            try:
                if mode.startswith("🔒"):
                    with st.spinner("🔐 Sedang mengenkripsi..."):
                        encrypt_file_hybrid(tmp_path, out_name, keyword)
                        # Simulasi progress (opsional, bisa dihapus jika prosesnya cepat)
                        # for i in range(100):
                        #     time.sleep(0.01)
                        #     progress.progress(i + 1)
                        progress.progress(100) # Langsung set 100% setelah selesai

                    elapsed = time.time() - t0
                    # Hitung throughput berdasarkan ukuran file ASLI
                    throughput = original_file_size_mb / elapsed if elapsed > 0 else 0
                    st.success(f"✅ Enkripsi selesai dalam {elapsed:.2f} detik (Throughput: {throughput:.2f} MB/s)")

                    with open(out_name, "rb") as f:
                        st.download_button(
                            "⬇️ Download File Terenkripsi (.hybr)",
                            f, file_name=os.path.basename(out_name)
                        )
                else: # Mode Dekripsi
                    with st.spinner("🔓 Sedang mendekripsi..."):
                        decrypt_file_hybrid(tmp_path, out_name, keyword)
                        # Simulasi progress (opsional)
                        # for i in range(100):
                        #     time.sleep(0.01)
                        #     progress.progress(i + 1)
                        progress.progress(100) # Langsung set 100%

                    elapsed = time.time() - t0
                    # Hitung throughput berdasarkan ukuran file ASLI (tmp_path) sebelum didekripsi
                    throughput = original_file_size_mb / elapsed if elapsed > 0 else 0
                    st.success(f"✅ Dekripsi selesai dalam {elapsed:.2f} detik (Throughput: {throughput:.2f} MB/s)")

                    with open(out_name, "rb") as f:
                        st.download_button(
                            "⬇️ Download File Asli",
                            f, file_name=os.path.basename(out_name)
                        )

            except ValueError as e:
                msg = str(e).lower()
                # Pesan error lebih spesifik
                if "key hex tidak valid" in msg:
                    st.error("❌ Keyword Myszkowski salah atau file .hybr korup.\nPastikan keyword sama persis.")
                elif "mac check failed" in msg or "integritas data terganggu" in msg:
                    st.error("⚠️ File terenkripsi tidak valid atau telah dimodifikasi (Tag GCM gagal).")
                elif "not a hybrid" in msg:
                    st.error("⚠️ File bukan hasil enkripsi (.hybr) yang valid (Magic Number salah).")
                elif "file korup" in msg or "file berakhir" in msg or "tag tidak lengkap" in msg:
                     st.error(f"⚠️ File terenkripsi tampaknya rusak atau tidak lengkap: {e}")
                else:
                    st.error(f"❌ Terjadi kesalahan Value: {e}")
            except Exception as e:
                st.error(f"❌ Error tak terduga: {e}")
            finally:
                # Selalu bersihkan file sementara
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass # Abaikan jika file sudah tidak ada

# ---------- Tombol Reset Session ----------
st.divider()
if st.button("🧹 Reset Keyword Session"):
    st.session_state.keyword = ""
    st.success("✅ Keyword telah dihapus dari sesi aktif.")
    st.rerun() # Refresh halaman untuk mengosongkan input box