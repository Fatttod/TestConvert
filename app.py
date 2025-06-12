# app.py (Dibuat ulang dari awal, sesuai request Mek)
import streamlit as st
import os
import sys
import logging
import base64 # Untuk encoding/decoding jika dibutuhkan (meskipun tidak langsung dipakai di app.py)
from github import Github, GithubException # Untuk interaksi dengan GitHub
import json # Untuk memparsing dan menampilkan JSON

# --- KONFIGURASI LOGGING ---
# Set up logging agar pesan log bisa dilihat di konsol Streamlit
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- KONFIGURASI GITHUB ---
# PENTING: GANTI ini dengan info repo lo, Mek!
# Ambil GitHub Token dari environment variable atau Streamlit Secrets
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN_VPN_BOT") 
REPO_OWNER = "FATTT"       # GANTI dengan username GitHub lo
REPO_NAME = "convert"      # GANTI dengan nama repository lo
BRANCH_NAME = "main"       # Atau "master", tergantung branch default repo lo

# --- Import Fungsi dari Modul Konverter Spesifik ---
# Pastikan singbox_converter.py ada di direktori yang sama dengan app.py
try:
    from singbox_converter import process_multiple_singbox_configs
    
    # Informasi modul konverter utama yang akan digunakan
    converter_config = {
        "function": process_multiple_singbox_configs, 
        "template_local_path": "singbox-template.txt", # Template diambil dari file lokal ini
        "output_mime": "application/json", # MIME type untuk file output JSON
        "output_language": "json",         # Syntax highlighting untuk kode JSON
        "output_github_files": [           # DAFTAR FILE OUTPUT SING-BOX YANG MAU BISA DIPILIH DI GITHUB
            {"display_name": "Main Config (singbox.txt)", "github_path": "singbox.txt"},
            # Bisa tambahin opsi lain di sini kalau ada template config lain (misal: singbox_gaming.txt)
            # {"display_name": "Gaming Config (singbox_gaming.txt)", "github_path": "singbox_gaming.txt"},
        ]
    }
except ImportError as e:
    st.error(f"❌ Error: Nggak bisa ngeload modul konverter. Pastikan 'singbox_converter.py' ada dan nggak ada error sintaks. Detail: {e}")
    logger.error(f"Failed to import singbox_converter: {e}", exc_info=True)
    st.stop() # Hentikan eksekusi aplikasi jika modul penting tidak bisa diimport
except Exception as e:
    st.error(f"❌ Error tak terduga saat inisialisasi konverter: {e}")
    logger.error(f"Unexpected error during converter initialization: {e}", exc_info=True)
    st.stop() # Hentikan eksekusi

# --- TAMPILAN UI STREAMLIT ---
st.set_page_config(layout="wide", page_title="VPN Config Converter") # Layout biar lebih lebar
st.title("VPN Config Converter 🚀")
st.markdown("Masukkan link VPN lo di bawah, Mek. Bisa VMess, VLESS, atau Trojan.")
st.markdown("---")

# Text area untuk input link VPN
uploaded_links = st.text_area(
    "Paste daftar link VPN di sini (satu link per baris, maksimal 50 link):",
    height=300,
    help="Contoh:\nvmess://eyJ2... (VMess link)\ntrojan://passwd@domain.com:443?type=ws&path=%2Fws#MyServer (Trojan link)\nvless://uuid@domain.com:443?type=ws&path=%2Fws&security=tls&sni=domain.com (VLESS link)"
)

# Pilihan output ke GitHub
st.subheader("Opsi Output (Pilih Salah Satu)")
output_to_github = st.checkbox("Upload Hasil ke GitHub?")

selected_output_github_path = None
if output_to_github:
    st.info("Pilih file di repo GitHub lo yang mau di-update.")
    # Membuat dictionary untuk mapping display_name ke github_path
    output_options_display = {opt["display_name"]: opt["github_path"] for opt in converter_config["output_github_files"]}
    
    if output_options_display:
        selected_display_name = st.selectbox(
            "Pilih file config GitHub:",
            list(output_options_display.keys()),
            help="Pilih file di repo GitHub lo yang akan di-update dengan config baru."
        )
        selected_output_github_path = output_options_display[selected_display_name]
    else:
        st.warning("Tod, belum ada opsi file output GitHub yang diset di kode 'converter_config'.")
        output_to_github = False # Matikan opsi GitHub kalau nggak ada pilihan

st.markdown("---")

# Tombol untuk memulai konversi
if st.button("Konversi Config Sekarang! 🔥"):
    if not uploaded_links:
        st.warning("Tod, belum ada link VPN yang dimasukin!")
    else:
        # Pisahkan link per baris dan filter yang kosong
        links_list = [link.strip() for link in uploaded_links.split('\n') if link.strip()]
        
        if not links_list:
            st.warning("Tod, belum ada link VPN yang dimasukin setelah dibersihkan!")
        elif len(links_list) > 50:
            st.warning(f"Mek, cuma bisa proses maksimal 50 link sekaligus. Lo masukin {len(links_list)} link. Kurangin dulu ya.")
        else:
            st.info(f"Oke Tod, siap proses {len(links_list)} link. Sabar bentar ya...")
            
            try:
                # Panggil fungsi konversi yang sudah diupdate untuk multiple links
                # Fungsi ini diharapkan mengembalikan:
                # - config_content (JSON utuh)
                # - processed_outbound_objects (list dari objek outbound individual)
                result = converter_config["function"](links_list, converter_config["template_local_path"])

                if result["status"] == "success":
                    new_config_content = result["config_content"]
                    # Ambil list objek outbound yang sudah diproses dari hasil
                    processed_outbound_objects = result.get("processed_outbound_objects", []) 
                    
                    st.success("🎉 Konversi berhasil, Tod!")
                    
                    # --- Bagian 1: Download Config Utama (Full Sing-Box JSON) ---
                    st.subheader("1. Config Utama (Download ini buat aplikasi Sing-Box lo)")
                    st.download_button(
                        label="⬇️ Download Config Baru (singbox.json)",
                        data=new_config_content,
                        file_name="singbox.json",
                        mime=converter_config["output_mime"],
                        help="Klik untuk download file config Sing-Box lengkap yang siap pakai."
                    )
                    
                    # Tampilkan kode config utuh (opsional, bisa di-truncate jika terlalu panjang)
                    MAX_DISPLAY_LENGTH = 50000 # Maksimal 50KB untuk ditampilkan di UI
                    if len(new_config_content) > MAX_DISPLAY_LENGTH:
                        st.info(f"Config terlalu besar ({len(new_config_content)} karakter) untuk ditampilkan semua di sini, Mek. Silakan download langsung ya!")
                    else:
                        st.code(new_config_content, language=converter_config["output_language"])

                    st.markdown("---")

                    # --- Bagian 2: Menampilkan Outbounds Per Bagian (untuk di-copy) ---
                    if processed_outbound_objects:
                        st.subheader("2. Outbounds yang Berhasil Dikonversi (Bisa di-Copy Per Bagian)")
                        
                        # Slider untuk memilih jumlah outbound per batch yang ditampilkan
                        # Defaultnya 10 atau jumlah total jika kurang dari 10
                        default_batch_size = min(10, len(processed_outbound_objects))
                        batch_size = st.slider(
                            "Jumlah Outbound per Batch:", 
                            min_value=1, 
                            max_value=len(processed_outbound_objects), 
                            value=default_batch_size, 
                            step=1,
                            help="Geser untuk mengatur berapa banyak outbound yang ditampilkan per blok. Ini biar gampang dicopy."
                        )
                        
                        num_batches = (len(processed_outbound_objects) + batch_size - 1) // batch_size
                        
                        for i in range(num_batches):
                            start_idx = i * batch_size
                            end_idx = min((i + 1) * batch_size, len(processed_outbound_objects))
                            
                            batch_outbounds = processed_outbound_objects[start_idx:end_idx]
                            
                            # Gunakan expander untuk setiap batch
                            with st.expander(f"Batch {i+1} (Outbound {start_idx+1}-{end_idx} dari {len(processed_outbound_objects)})"):
                                for j, outbound_obj in enumerate(batch_outbounds):
                                    outbound_tag = outbound_obj.get('tag', f"Outbound-{start_idx+j+1}") # Ambil tag atau pakai default
                                    st.markdown(f"**Tag:** `{outbound_tag}`")
                                    st.code(json.dumps(outbound_obj, indent=2), language="json", key=f"outbound_display_{start_idx+j}") # key for uniqueness
                                    st.markdown("---") # Separator antar outbound dalam batch
                    else:
                        st.info("Tod, nggak ada outbound yang berhasil dikonversi dari link yang lo kasih.")

                    # --- Bagian 3: Upload ke GitHub ---
                    if output_to_github and selected_output_github_path:
                        if not GITHUB_TOKEN or GITHUB_TOKEN == "ISI_TOKEN_GITHUB_LO": # Cek token belum diganti
                            st.error("❌ TOKEN GITHUB BELUM DISET, MEK! Cek `GITHUB_TOKEN_VPN_BOT` lo di Streamlit Secrets lo atau di `.env` file.")
                        else:
                            try:
                                g = Github(GITHUB_TOKEN)
                                repo = g.get_user().get_repo(REPO_NAME) # Akses repo berdasarkan REPO_NAME
                                
                                # Cek apakah file sudah ada di GitHub
                                try:
                                    contents = repo.get_contents(selected_output_github_path, ref=BRANCH_NAME)
                                    # Jika file ada, update kontennya
                                    repo.update_file(
                                        contents.path,
                                        f"Update config Sing-Box dari aplikasi VPN Converter",
                                        new_config_content,
                                        contents.sha,
                                        branch=BRANCH_NAME
                                    )
                                    st.success(f"✅ Config berhasil diupdate di GitHub: `{selected_output_github_path}`")
                                except GithubException as e:
                                    if e.status == 404:
                                        # Jika file tidak ada (404 Not Found), buat baru
                                        repo.create_file(
                                            selected_output_github_path,
                                            f"Buat config Sing-Box dari aplikasi VPN Converter",
                                            new_config_content,
                                            branch=BRANCH_NAME
                                        )
                                        st.success(f"✅ Config baru berhasil dibuat di GitHub: `{selected_output_github_path}`")
                                    else:
                                        raise # Lempar error ke except di bawah jika bukan 404
                                
                                # Tampilkan link ke file di GitHub agar mudah diakses
                                st.markdown(f"Lihat hasilnya di GitHub: `{repo.html_url}/blob/{BRANCH_NAME}/{selected_output_github_path}`")
                                    
                            except GithubException as e:
                                st.error(f"❌ Gagal konek ke GitHub API. Cek GITHUB_TOKEN_VPN_BOT lo atau izin akses token. Error: {e.data.get('message', str(e))}")
                                logger.error(f"GitHub connection error: {e.data.get('message', str(e))}", exc_info=True)
                            except Exception as e:
                                st.error(f"❌ Terjadi error tak terduga saat mencoba konek ke GitHub: {e}")
                                logger.error(f"Unexpected GitHub connection error: {e}", exc_info=True)

                elif result["status"] == "warning":
                    st.warning(result["message"])
                else: # result["status"] == "error"
                    st.error(result["message"])
                    st.error("Lihat log Streamlit lo buat detail errornya, Mek!")

            except Exception as e:
                st.error(f"❌ Terjadi error saat memproses: {e}")
                logger.error(f"Overall processing error: {e}", exc_info=True)


st.markdown("---")
st.caption("Dibuat dengan 🔥 oleh teman lo.")

# Tambahan untuk Termux/lingkungan lokal
if __name__ == '__main__':
    if sys.version_info < (3, 7):
        st.error("Mek, butuh Python 3.7 atau lebih baru ya buat jalanin bot ini.")
        sys.exit(1)
    
    # Pesan ini hanya akan muncul saat dijalankan secara lokal (bukan di Streamlit Cloud)
    logger.info("Aplikasi Streamlit berjalan. Akses dari browser lo di http://localhost:8501")
                              
