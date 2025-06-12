# app.py (Disinkronkan dengan singbox_converter.py milik FATTT)
import streamlit as st
import os
import sys
import logging
import base64
from github import Github, GithubException 
import json # Untuk memparsing dan menampilkan JSON (jika perlu)

# --- KONFIGURASI LOGGING ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- KONFIGURASI GITHUB ---
# PENTING: Ambil GitHub Token dari environment variable atau Streamlit Secrets
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN_VPN_BOT") 
REPO_OWNER = "FATTT"       # Sesuai permintaan lo
REPO_NAME = "convert"      # Sesuai permintaan lo
BRANCH_NAME = "main"       # Atau "master", tergantung branch default repo lo

# --- Import Fungsi dari Modul Konverter Spesifik ---
try:
    # Memanggil fungsi 'process_singbox_config' dari singbox_converter.py milik lo
    from singbox_converter import process_singbox_config
    
    converter_config = {
        "function": process_singbox_config, 
        "template_local_path": "singbox-template.txt", 
        "output_mime": "application/json", 
        "output_language": "json",         
        "output_github_files": [           
            {"display_name": "Main Config (singbox.txt)", "github_path": "singbox.txt"},
            # Tambahkan opsi lain di sini jika ada file config lain di GitHub lo
            # {"display_name": "Gaming Config (singbox_gaming.txt)", "github_path": "singbox_gaming.txt"},
        ]
    }
except ImportError as e:
    st.error(f"❌ Error: Nggak bisa ngeload modul konverter. Pastikan 'singbox_converter.py' ada dan nggak ada error sintaks. Detail: {e}")
    logger.error(f"Failed to import singbox_converter: {e}", exc_info=True)
    st.stop() 
except Exception as e:
    st.error(f"❌ Error tak terduga saat inisialisasi konverter: {e}")
    logger.error(f"Unexpected error during converter initialization: {e}", exc_info=True)
    st.stop() 

# --- TAMPILAN UI STREAMLIT ---
st.set_page_config(layout="wide", page_title="VPN Config Converter") 
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
        output_to_github = False 

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
                # Panggil fungsi konversi dari singbox_converter.py milik lo
                result = converter_config["function"](links_list, converter_config["template_local_path"])

                if result["status"] == "success":
                    new_config_content = result["config_content"]
                    
                    st.success("🎉 Konversi berhasil, Tod!")
                    
                    # --- Bagian 1: Download Config Utama (Full Sing-Box JSON) ---
                    st.subheader("Config Utama (Download ini buat aplikasi Sing-Box lo)")
                    st.download_button(
                        label="⬇️ Download Config Baru (singbox.json)",
                        data=new_config_content,
                        file_name="singbox.json",
                        mime=converter_config["output_mime"],
                        help="Klik untuk download file config Sing-Box lengkap yang siap pakai."
                    )
                    
                    # Tampilkan kode config utuh (opsional, bisa di-truncate jika terlalu panjang)
                    MAX_DISPLAY_LENGTH = 50000 
                    if len(new_config_content) > MAX_DISPLAY_LENGTH:
                        st.info(f"Config terlalu besar ({len(new_config_content)} karakter) untuk ditampilkan semua di sini, Mek. Silakan download langsung ya!")
                    else:
                        st.code(new_config_content, language=converter_config["output_language"])

                    st.markdown("---")

                    # --- Bagian 2: Upload ke GitHub (jika dipilih) ---
                    if output_to_github and selected_output_github_path:
                        if not GITHUB_TOKEN: 
                            st.error("❌ TOKEN GITHUB BELUM DISET, MEK! Cek `GITHUB_TOKEN_VPN_BOT` lo di Streamlit Secrets atau `.env` file lo.")
                        else:
                            try:
                                g = Github(GITHUB_TOKEN)
                                repo = g.get_user().get_repo(REPO_NAME) 
                                
                                try:
                                    contents = repo.get_contents(selected_output_github_path, ref=BRANCH_NAME)
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
                                        repo.create_file(
                                            selected_output_github_path,
                                            f"Buat config Sing-Box dari aplikasi VPN Converter",
                                            new_config_content,
                                            branch=BRANCH_NAME
                                        )
                                        st.success(f"✅ Config baru berhasil dibuat di GitHub: `{selected_output_github_path}`")
                                    else:
                                        raise 
                                
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
    
    logger.info("Aplikasi Streamlit berjalan. Akses dari browser lo di http://localhost:8501")
  
