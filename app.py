# app.py (Revisi untuk template lokal, hasil ke GitHub/Download)
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

# --- KONFIGURASI GITHUB ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN_VPN_BOT") 
REPO_OWNER = "NamaUsernameLoDiGitHub" # GANTI ini dengan info repo lo
REPO_NAME = "MySingBoxConfigs"      # GANTI ini dengan info repo lo
BRANCH_NAME = "main"                # Atau "master", tergantung branch default repo lo

# --- Import Fungsi dari Modul Konverter Spesifik ---
converter_modules = {}

try:
    from singbox_converter import process_singbox_config
    converter_modules["Sing-Box"] = {
        "function": process_singbox_config, 
        "template_local_path": "singbox-template.txt", # Template diambil dari file lokal ini
        "output_mime": "application/json", 
        "output_language": "json",
        "output_options": [ # DAFTAR FILE OUTPUT SING-BOX YANG MAU BISA DIPILIH DI GITHUB
            {"display_name": "Main Config (singbox.txt)", "github_path": "singbox.txt"},
            {"display_name": "Gaming Config (singbox_gaming.txt)", "github_path": "singbox_gaming.txt"},
            # Tambahin lagi kalo ada file output Sing-Box lain yang mau bisa diupdate
        ]
    }
    logger.info("Modul 'singbox_converter.py' berhasil diimpor.")
except ImportError:
    logger.warning("Gagal mengimpor 'singbox_converter.py'. Opsi Sing-Box tidak akan tersedia.")

try:
    from clash_converter import process_clash_config
    converter_modules["Clash (YAML)"] = {
        "function": process_clash_config, 
        "template_local_path": "clash-template.yaml", # Template diambil dari file lokal ini
        "output_mime": "application/yaml", 
        "output_language": "yaml",
        "output_options": [ # DAFTAR FILE OUTPUT CLASH YANG MAU BISA DIPILIH DI GITHUB
            {"display_name": "Main Clash Config (clash.yaml)", "github_path": "clash.yaml"},
            # Tambahin lagi kalo ada file output Clash lain
        ]
    }
    logger.info("Modul 'clash_converter.py' berhasil diimpor.")
except ImportError:
    logger.warning("Gagal mengimpor 'clash_converter.py'. Opsi Clash tidak akan tersedia.")


if not converter_modules:
    st.error("Error: Tidak ada modul konverter yang berhasil diimpor. Pastikan file konverter (.py) ada.")
    st.stop()

# --- UI Streamlit ---
st.set_page_config(page_title="VPN Config Converter", layout="centered")

st.title("🚀 Konversi Link VPN ke Berbagai Config")
st.markdown("---")

st.write("Halo, Tod! Masukin aja link VPN lo di sini (bisa banyak link digabung).")
st.write("Nanti gua konversi jadi config yang siap pakai.")

# Pilihan tipe konversi dari modul yang berhasil diimpor
conversion_options = list(converter_modules.keys())
if not conversion_options:
    st.error("Tidak ada opsi konversi yang tersedia.")
    st.stop()

selected_conversion_type = st.radio(
    "Pilih Tipe Konfigurasi Output:",
    conversion_options,
    index=0 
)

# Ambil info konverter yang dipilih
selected_converter_info = converter_modules[selected_conversion_type]
conversion_function = selected_converter_info["function"]
template_local_path = selected_converter_info["template_local_path"] # Path template lokal
output_mime_type = selected_converter_info["output_mime"]
output_language = selected_converter_info["output_language"]

# Cek keberadaan file template lokal
if not os.path.exists(template_local_path):
    st.error(f"❌ Error: File template lokal '{template_local_path}' tidak ditemukan.")
    st.warning("Pastikan file template ada di folder yang sama dengan `app.py`.")
    st.stop()

st.markdown("---")
st.subheader("Pilih File Tujuan Output:")

# --- RADIO BUTTON UNTUK PILIH FILE OUTPUT DI GITHUB ---
# Opsi output ke GitHub hanya muncul jika GITHUB_TOKEN ada
output_target_options = ["Download Langsung"]
if GITHUB_TOKEN:
    output_target_options.append("Upload ke GitHub Repository")

selected_output_target = st.radio(
    "Pilih bagaimana hasil konversi akan dikelola:",
    output_target_options,
    index=0 # Default: Download Langsung
)

output_github_path = None # Default
output_filename_for_download = "result." + ("json" if output_mime_type == "application/json" else "yaml") # Default filename for download

if selected_output_target == "Upload ke GitHub Repository":
    output_display_names = [opt["display_name"] for opt in selected_converter_info["output_options"]]
    selected_output_display_name = st.radio(
        "Pilih file di GitHub yang ingin diupdate:",
        output_display_names,
        index=0 # Default pilih yang pertama
    )

    selected_output_obj = next(
        (opt for opt in selected_converter_info["output_options"] if opt["display_name"] == selected_output_display_name), 
        None
    )

    if not selected_output_obj:
        st.error("Error: File output tujuan yang dipilih tidak ditemukan.")
        st.stop()
    
    output_github_path = selected_output_obj["github_path"]
    output_filename_for_download = os.path.basename(output_github_path) # Gunakan nama file GitHub untuk download juga
    st.info(f"Menggunakan template lokal: `{template_local_path}`. Hasil akan diupload ke: `{output_github_path}`.")
else:
    st.info(f"Menggunakan template lokal: `{template_local_path}`. Hasil akan di-download langsung.")


# Input area untuk link VPN
vpn_links_input = st.text_area(
    "Paste Link VPN Lo Di Sini (Trojan, VLESS, VMess):",
    height=200,
    placeholder="Contoh:\nvless://uuid@server:port?security=tls&type=ws&path=%2Fws&host=example.com#MyVPN\ntrojan://password@server:port?security=tls&type=grpc&serviceName=gRPC#AnotherVPN"
)

st.markdown("---")


# Tombol konversi
if st.button("Konversi dan Proses!"):
    if not vpn_links_input.strip():
        st.warning("Eits, Tod! Belum ada link VPN yang dimasukkin.")
    elif not conversion_function:
        st.info("Pilih tipe konversi yang tersedia dulu ya, Mek!")
    else:
        with st.spinner("⏳ Lagi proses, Mek... Membaca template, mengkonversi, dan memproses output... Sabar ya."):
            try:
                # 1. Baca template dari file lokal
                try:
                    with open(template_local_path, 'r', encoding='utf-8') as f:
                        template_content = f.read()
                    logger.info(f"Berhasil membaca '{template_local_path}' (template lokal).")
                except Exception as e:
                    st.error(f"❌ Error saat membaca template lokal '{template_local_path}': {e}")
                    logger.error(f"Local template read error: {e}", exc_info=True)
                    st.stop()

                # 2. Panggil fungsi logika dari modul terpisah dengan content template
                result = conversion_function(
                    vpn_links_input, 
                    template_content # Kirim langsung content template yang sudah dibaca dari lokal
                )
                
                if result["status"] == "success":
                    st.success(f"🎉 Sukses, Tod! Konfigurasi sudah dibuat.")
                    st.subheader(f"🎉 Config {selected_conversion_type} Lo:")
                    st.code(result["config_content"], language=output_language)

                    # --- Handle Pilihan Output ---
                    if selected_output_target == "Download Langsung":
                        st.download_button(
                            label=f"💾 Download {output_filename_for_download}",
                            data=result["config_content"],
                            file_name=output_filename_for_download,
                            mime=output_mime_type
                        )
                        st.info("File sudah siap di-download langsung dari browser lo.")
                    
                    elif selected_output_target == "Upload ke GitHub Repository":
                        if not GITHUB_TOKEN: # Ini sudah di cek di awal
                            st.error("❌ Gagal upload ke GitHub: GITHUB_TOKEN_VPN_BOT environment variable belum diset.")
                            st.warning("Pastikan lo sudah set token GitHub di lingkungan Termux lo (`export GITHUB_TOKEN_VPN_BOT=...`).")
                        elif not output_github_path: # Pastikan path tujuan GitHub sudah terpilih
                             st.error("❌ Error: Path tujuan GitHub belum dipilih. Refresh halaman dan coba lagi.")
                        else:
                            with st.spinner("🚀 Uploading ke GitHub..."):
                                try:
                                    g = Github(GITHUB_TOKEN)
                                    repo = g.get_user(REPO_OWNER).get_repo(REPO_NAME)
                                    
                                    commit_message = f"Update {output_github_path} via VPN Converter Bot ({selected_conversion_type})"
                                    
                                    try:
                                        contents_to_update = repo.get_contents(output_github_path, ref=BRANCH_NAME)
                                        repo.update_file(
                                            path=output_github_path,
                                            message=commit_message,
                                            content=result["config_content"],
                                            sha=contents_to_update.sha, 
                                            branch=BRANCH_NAME
                                        )
                                        st.success(f"✅ Berhasil mengupdate `{output_github_path}` di GitHub!")
                                    except GithubException as e:
                                        if e.status == 404:
                                            repo.create_file(
                                                path=output_github_path,
                                                message=commit_message,
                                                content=result["config_content"],
                                                branch=BRANCH_NAME
                                            )
                                            st.success(f"✅ Berhasil membuat file `{output_github_path}` baru di GitHub!")
                                        else:
                                            st.error(f"❌ Error GitHub saat mengupload: {e.data.get('message', str(e))}")
                                            logger.error(f"GitHub upload error: {e.data.get('message', str(e))}", exc_info=True)
                                    except Exception as e:
                                        st.error(f"❌ Terjadi error saat upload ke GitHub: {e}")
                                        logger.error(f"Generic upload error: {e}", exc_info=True)
                                    
                                    st.info(f"Lihat hasilnya di GitHub: `https://github.com/{REPO_OWNER}/{REPO_NAME}/blob/{BRANCH_NAME}/{output_github_path}`")
                                    
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

