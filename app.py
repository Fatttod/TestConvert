# app.py (Bisa Update Repo Lain & Ganti Path File Target, kompatibel dengan singbox_converter.py FATTT)
import streamlit as st
import os
import sys
import logging
import base64 
from github import Github, GithubException 
import json 

# --- KONFIGURASI LOGGING ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- KONFIGURASI GITHUB HOSTING (REPO TEMPAT APP.PY INI BERADA) ---
# Info ini HANYA untuk Streamlit mengenali di repo mana aplikasi ini di-host.
# File output TIDAK akan di-push ke sini, melainkan ke repo TARGET yang diinput.
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN_VPN_BOT") 
HOSTING_REPO_OWNER = "FATTT"      
HOSTING_REPO_NAME = "convert"     
HOSTING_BRANCH_NAME = "main"      

# --- Import Fungsi dari Modul Konverter Spesifik ---
try:
    from singbox_converter import process_singbox_config
    
    converter_config = {
        "function": process_singbox_config, 
        "template_local_path": "singbox-template.txt", 
        "output_mime": "application/json", 
        "output_language": "json",         
        # "github_target_file" dihapus dari sini, karena akan diambil dari inputan UI
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

st.markdown("---")

# Bagian Input Repo Target
st.subheader("Pengaturan Repository GitHub Target")
st.info("Masukkan detail repo GitHub yang ingin lo update config-nya. Pastikan token lo punya izin akses ke repo ini.")

target_repo_owner = st.text_input(
    "Owner Repository Target (username atau nama organisasi)",
    value="FATTT", 
    help="Username GitHub atau nama organisasi pemilik repo target."
)
target_repo_name = st.text_input(
    "Nama Repository Target",
    value="singbox-configs", # Contoh nama repo target, bisa lo ganti
    help="Nama repo GitHub yang akan di-update config-nya."
)
target_branch_name = st.text_input(
    "Branch Target",
    value="main", # Default branch target
    help="Nama branch di repo target (biasanya 'main' atau 'master')."
)
target_file_path = st.text_input( # INPUT BARU UNTUK PATH FILE TARGET
    "Path File Target di Repository GitHub (misal: singbox.json atau configs/my-config.txt)",
    value="singbox.json", # Default path file
    help="Path dan nama file di dalam repo target yang akan di-update atau dibuat."
)

st.markdown("---")

# Tombol untuk memulai konversi dan upload
if st.button("Konversi & Update GitHub/Download Config 🔥"):
    if not uploaded_links:
        st.warning("Tod, belum ada link VPN yang dimasukin!")
    else:
        links_list = [link.strip() for link in uploaded_links.split('\n') if link.strip()]
        
        if not links_list:
            st.warning("Tod, belum ada link VPN yang dimasukin setelah dibersihkan!")
        elif len(links_list) > 50:
            st.warning(f"Mek, cuma bisa proses maksimal 50 link sekaligus. Lo masukin {len(links_list)} link. Kurangin dulu ya.")
        elif not target_repo_owner or not target_repo_name or not target_file_path: # Validasi path file
            st.warning("Tod, nama owner, nama repo, atau path file target GitHub nggak boleh kosong!")
        else:
            st.info(f"Oke Tod, siap proses {len(links_list)} link dan update file `{target_file_path}` di repo `{target_repo_owner}/{target_repo_name}`. Sabar bentar ya...")
            
            try:
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
                    
                    MAX_DISPLAY_LENGTH = 50000 
                    if len(new_config_content) > MAX_DISPLAY_LENGTH:
                        st.info(f"Config terlalu besar ({len(new_config_content)} karakter) untuk ditampilkan semua di sini, Mek. Silakan download langsung ya!")
                    else:
                        st.code(new_config_content, language=converter_config["output_language"])

                    st.markdown("---")

                    # --- Bagian 2: Upload ke GitHub Target ---
                    st.subheader("Update GitHub Repository Target")
                    if not GITHUB_TOKEN: 
                        st.error("❌ TOKEN GITHUB BELUM DISET, MEK! Cek `GITHUB_TOKEN_VPN_BOT` lo di Streamlit Secrets atau `.env` file lo.")
                        st.warning("Tanpa GitHub token, fitur update repo tidak bisa berjalan.")
                    else:
                        try:
                            g = Github(GITHUB_TOKEN)
                            repo = g.get_user(target_repo_owner).get_repo(target_repo_name) 
                            # target_file_path sudah diambil dari inputan UI

                            try:
                                contents = repo.get_contents(target_file_path, ref=target_branch_name)
                                repo.update_file(
                                    contents.path,
                                    f"Update config Sing-Box dari aplikasi VPN Converter",
                                    new_config_content,
                                    contents.sha,
                                    branch=target_branch_name
                                )
                                st.success(f"✅ Config berhasil diupdate di GitHub: `{target_repo_owner}/{target_repo_name}/{target_file_path}`")
                            except GithubException as e:
                                if e.status == 404:
                                    repo.create_file(
                                        target_file_path,
                                        f"Buat config Sing-Box dari aplikasi VPN Converter",
                                        new_config_content,
                                        branch=target_branch_name
                                    )
                                    st.success(f"✅ Config baru berhasil dibuat di GitHub: `{target_repo_owner}/{target_repo_name}/{target_file_path}`")
                                else:
                                    raise 
                            
                            st.markdown(f"Lihat hasilnya di GitHub: `{repo.html_url}/blob/{target_branch_name}/{target_file_path}`")
                                
                        except GithubException as e:
                            st.error(f"❌ Gagal konek ke GitHub API untuk repo target. Cek GITHUB_TOKEN_VPN_BOT lo (harus punya izin ke repo target) atau detail repo target yang lo masukin. Error: {e.data.get('message', str(e))}")
                            logger.error(f"GitHub connection error to target repo: {e.data.get('message', str(e))}", exc_info=True)
                        except Exception as e:
                            st.error(f"❌ Terjadi error tak terduga saat mencoba konek ke GitHub target: {e}")
                            logger.error(f"Unexpected GitHub connection error to target repo: {e}", exc_info=True)

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

if __name__ == '__main__':
    if sys.version_info < (3, 7):
        st.error("Mek, butuh Python 3.7 atau lebih baru ya buat jalanin bot ini.")
        sys.exit(1)
    
    logger.info("Aplikasi Streamlit berjalan. Akses dari browser lo di http://localhost:8501")
  
