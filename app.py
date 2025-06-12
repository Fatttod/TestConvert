# app.py (Revisi untuk template lokal, hasil ke GitHub/Download)
import streamlit as st
import os
import sys
import logging
import base64 # Tetap butuh base64 untuk encode content ke GitHub
from github import Github, GithubException 

# Set up basic logging for Streamlit app
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',\
                    level=logging.INFO,\
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- KONFIGURASI GITHUB ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN_VPN_BOT") 
REPO_OWNER = "FATTT" # GANTI ini dengan info repo lo
REPO_NAME = "convert"      # GANTI ini dengan info repo lo
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
            {"display_name": "Gaming Config (singbox_gaming.txt)", "github_path": "singbox_gaming.txt"} # Contoh lain
        ]
    }
except ImportError:
    st.error("Gagal memuat singbox_converter.py. Pastikan file ada dan tidak ada error sintaks.")
    logger.error("Failed to import singbox_converter.py", exc_info=True)
except Exception as e:
    st.error(f"Terjadi error saat inisialisasi converter: {e}")
    logger.error(f"Error during converter module initialization: {e}", exc_info=True)


# --- JUDUL APLIKASI ---
st.title("🧰 VPN Config Converter by Mek")
st.markdown("---")

# --- PILIH TIPE KONVERSI ---
st.subheader("1. Pilih Tipe Konverter")
selected_converter_name = st.selectbox(
    "Pilih jenis config yang mau lo buat:",
    list(converter_modules.keys())
)
selected_converter = converter_modules.get(selected_converter_name)

if selected_converter:
    st.info(f"Lo milih {selected_converter_name} Converter. Pastiin format link VPN lo bener ya!")

    # --- INPUT LINK VPN ---
    st.subheader("2. Masukin Link VPN lo")
    vmess_links_input = st.text_area(
        "Paste link VMess/VLESS/Trojan lo di sini (satu link per baris):",
        height=200,
        placeholder="Contoh:\nvmess://eyJhZGQ...",
        key="vpn_links_input"
    )

    # --- OPSI OUTPUT ---
    st.subheader("3. Pilih Output")
    output_location = st.radio(
        "Mau hasil konversinya diapain?",
        ("Download File", "Upload ke GitHub"),
        key="output_location"
    )

    selected_github_option = None
    if output_location == "Upload ke GitHub":
        if selected_converter.get("output_options"):
            display_names = [opt["display_name"] for opt in selected_converter["output_options"]]
            selected_display_name = st.selectbox(
                "Pilih file output untuk GitHub:",
                display_names,
                key="github_output_option"
            )
            selected_github_option = next((opt for opt in selected_converter["output_options"] if opt["display_name"] == selected_display_name), None)
        else:
            st.warning("Nggak ada opsi file output yang ditentuin buat GitHub.")
    
    # --- TOMBOL KONVERSI ---
    st.markdown("---")
    if st.button("🚀 Konversi Sekarang!"):
        if not vmess_links_input:
            st.warning("Eh, link VPN-nya belum lo masukkin, Mek!")
        elif not selected_converter:
            st.error("Tipe konverter nggak valid.")
        else:
            converter_func = selected_converter["function"]
            template_local_path = selected_converter["template_local_path"]
            
            try:
                # Baca template dari file lokal
                with open(template_local_path, 'r', encoding='utf-8') as f:
                    template_content = f.read()
                
                # --- DEBUGGING DI APP.PY SEBELUM MEMANGGIL CONVERTER ---
                logger.debug(f"app.py: Template content loaded (first 200 chars): {template_content[:200]}...")
                logger.debug(f"app.py: VMess links input (first 200 chars): {vmess_links_input[:200]}...")
                # --- AKHIR DEBUGGING ---

                result = converter_func(vmess_links_input, template_content, selected_converter["output_options"])
                
                # --- DEBUGGING DI APP.PY SETELAH MEMANGGIL CONVERTER ---
                logger.debug(f"app.py: Result status from converter: {result.get('status')}")
                if "config_content" in result:
                    logger.debug(f"app.py: Result config_content received (first 200 chars): {result['config_content'][:200]}...")
                    logger.debug(f"app.py: Type of result['config_content']: {type(result['config_content'])}")
                else:
                    logger.debug("app.py: 'config_content' not found in result.")
                # --- AKHIR DEBUGGING ---

                if result["status"] == "success":
                    st.success(result["message"])
                    generated_config = result["config_content"] # Ini sudah string JSON

                    if output_location == "Download File":
                        output_filename = selected_converter_name.lower().replace(" ", "_") + "_config.json"
                        st.download_button(
                            label=f"⬇️ Download {selected_converter_name} Config",
                            data=generated_config.encode(selected_converter["output_mime"]), # Encode to bytes for download
                            file_name=output_filename,
                            mime=selected_converter["output_mime"],
                            key="download_button"
                        )
                        st.code(generated_config, language=selected_converter["output_language"])

                    elif output_location == "Upload ke GitHub":
                        if not GITHUB_TOKEN:
                            st.error("❌ GITHUB_TOKEN_VPN_BOT belum diset di environment variables lo!")
                        elif not selected_github_option:
                            st.warning("Pilih dulu file output yang mau di-upload ke GitHub!")
                        else:
                            try:
                                # Inisialisasi GitHub
                                g = Github(GITHUB_TOKEN)
                                repo = g.get_user(REPO_OWNER).get_repo(REPO_NAME)
                                
                                output_github_path = selected_github_option["github_path"]
                                commit_message = f"Update {output_github_path} via VPN Bot Streamlit"

                                try:
                                    # Coba dapatkan file yang sudah ada
                                    contents = repo.get_contents(output_github_path, ref=BRANCH_NAME)
                                    # Update file
                                    repo.update_file(
                                        contents.path,
                                        commit_message,
                                        generated_config, # Konten sudah string, tidak perlu encode lagi
                                        contents.sha,
                                        branch=BRANCH_NAME
                                    )
                                    st.success(f"✅ File `{output_github_path}` berhasil diupdate di GitHub!")
                                except GithubException as e:
                                    if e.status == 404:
                                        # File tidak ditemukan, buat baru
                                        repo.create_file(
                                            output_github_path,
                                            commit_message,
                                            generated_config, # Konten sudah string, tidak perlu encode lagi
                                            branch=BRANCH_NAME
                                        )
                                        st.success(f"✅ File `{output_github_path}` berhasil dibuat di GitHub!")
                                    else:
                                        raise # Re-raise error lain
                                
                                st.markdown(f"Link file di GitHub: `{repo.html_url}/blob/{BRANCH_NAME}/{output_github_path}`")
                                    
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

