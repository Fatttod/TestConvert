# app.py (Revisi untuk template lokal, hasil ke GitHub/Download, dan Multiple Links)
import streamlit as st
import os
import sys
import logging
import base64 # Tetap butuh base64 untuk encode content ke GitHub
from github import Github, GithubException 

# Set up basic logging for Streamlit app
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- KONFIGURASI GITHUB ---\n
# PENTING: GANTI ini dengan info repo lo, Mek!
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN_VPN_BOT") 
REPO_OWNER = "NamaUsernameLoDiGitHub" 
REPO_NAME = "MySingBoxConfigs"      
BRANCH_NAME = "main"                

# --- Import Fungsi dari Modul Konverter Spesifik ---
# Sekarang kita import fungsi untuk memproses BANYAK link sekaligus
try:
    from singbox_converter import process_multiple_singbox_configs
    converter_module = {
        "function": process_multiple_singbox_configs, 
        "template_local_path": "singbox-template.txt", # Template diambil dari file lokal ini
        "output_mime": "application/json", 
        "output_language": "json",
        "output_options": [ # DAFTAR FILE OUTPUT SING-BOX YANG MAU BISA DIPILIH DI GITHUB
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
    st.stop()

st.title("VPN Config Converter 🚀")
st.markdown("Masukkan link VPN lo di bawah, Mek. Bisa VMess, VLESS, atau Trojan.")
st.markdown("---")

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
    output_options_display = {opt["display_name"]: opt["github_path"] for opt in converter_module["output_options"]}
    
    if output_options_display:
        selected_display_name = st.selectbox(
            "Pilih file config GitHub:",
            list(output_options_display.keys())
        )
        selected_output_github_path = output_options_display[selected_display_name]
    else:
        st.warning("Tod, belum ada opsi file output GitHub yang diset di kode.")
        output_to_github = False # Matikan opsi GitHub kalau nggak ada pilihan

st.markdown("---")

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
                result = converter_module["function"](links_list, converter_module["template_local_path"])

                if result["status"] == "success":
                    new_config_content = result["config_content"]
                    st.success("🎉 Konversi berhasil, Tod!")
                    st.code(new_config_content, language=converter_module["output_language"])

                    # Tombol download
                    st.download_button(
                        label="⬇️ Download Config Baru (singbox.json)",
                        data=new_config_content,
                        file_name="singbox.json",
                        mime=converter_module["output_mime"]
                    )

                    if output_to_github and selected_output_github_path:
                        if not GITHUB_TOKEN or GITHUB_TOKEN == "ISI_TOKEN_GITHUB_LO":
                            st.error("❌ TOKEN GITHUB BELUM DISET, MEK! Cek `GITHUB_TOKEN_VPN_BOT` di Streamlit Secrets lo atau di `.env` file.")
                        else:
                            try:
                                g = Github(GITHUB_TOKEN)
                                repo = g.get_user().get_repo(REPO_NAME)
                                
                                # Cek apakah file sudah ada
                                try:
                                    contents = repo.get_contents(selected_output_github_path, ref=BRANCH_NAME)
                                    # Jika file ada, update
                                    repo.update_file(
                                        contents.path,
                                        f"Update config Sing-Box dari aplikasi",
                                        new_config_content,
                                        contents.sha,
                                        branch=BRANCH_NAME
                                    )
                                    st.success(f"✅ Config berhasil diupdate di GitHub: `{selected_output_github_path}`")
                                except GithubException as e:
                                    if e.status == 404:
                                        # Jika file tidak ada, buat baru
                                        repo.create_file(
                                            selected_output_github_path,
                                            f"Buat config Sing-Box dari aplikasi",
                                            new_config_content,
                                            branch=BRANCH_NAME
                                        )
                                        st.success(f"✅ Config baru berhasil dibuat di GitHub: `{selected_output_github_path}`")
                                    else:
                                        raise # Lempar error ke except di bawah jika bukan 404
                                
                                # Tampilkan link ke file di GitHub
                                st.markdown(f"Lihat hasilnya di GitHub: `{repo.html_url}/blob/{BRANCH_NAME}/{selected_output_github_path}`")
                                    
                            except GithubException as e:
                                st.error(f"❌ Gagal konek ke GitHub API. Cek GITHUB_TOKEN_VPN_BOT lo. Error: {e.data.get('message', str(e))}")
                                logger.error(f"GitHub connection error: {e.data.get('message', str(e))}", exc_info=True)
                            except Exception as e:
                                st.error(f"❌ Terjadi error tak terduga saat mencoba konek ke GitHub: {e}")
                                logger.error(f"Unexpected GitHub connection error: {e}", exc_info=True)

                elif result["status"] == "warning":
                    st.warning(result["message"])
                else: # error
                    st.error(result["message"])
                    st.error("Lihat log Termux lo buat detail errornya, Mek!")

            except Exception as e:
                st.error(f"❌ Terjadi error saat memproses: {e}")
                logger.error(f"Overall processing error: {e}", exc_info=True)


st.markdown("---")
st.caption("Dibuat dengan 🔥 oleh teman lo.")

# Tambahan untuk Termux
if __name__ == '__main__':
    if sys.version_info < (3, 7):
        st.error("Mek, butuh Python 3.7 atau lebih baru ya buat jalanin bot ini.")
        sys.exit(1)
    
    logger.info("Aplikasi Streamlit berjalan. Akses dari browser lo di http://localhost:8501")
