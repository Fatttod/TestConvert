import streamlit as st
import os
import sys
import logging
from github import Github, GithubException
import json # Tambahkan ini untuk validasi JSON

# Import fungsi konversi dari file terpisah
# Pastikan singbox_converter.py ada di direktori yang sama dengan app.py
from singbox_converter import process_singbox_config 

# --- KONFIGURASI LOGGING ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- FUNGSI UPDATE GITHUB FILE ---
def update_github_file(repo, file_path, new_content, commit_message):
    try:
        try:
            contents = repo.get_contents(file_path, ref="main") # Asumsi branch default adalah 'main'
            repo.update_file(contents.path, commit_message, new_content, contents.sha, branch="main")
            st.success(f"File '{file_path}' updated successfully in '{repo.full_name}'.")
        except GithubException as e:
            if e.status == 404: # File tidak ditemukan, buat file baru
                repo.create_file(file_path, commit_message, new_content, branch="main")
                st.success(f"File '{file_path}' created successfully in '{repo.full_name}'.")
            else:
                st.error(f"GitHub Error updating/creating file '{file_path}': {e.data.get('message', 'Unknown error')}")
                logger.error(f"Failed to update/create file '{file_path}' in '{repo.full_name}': {e}", exc_info=True)
                return False
        return True
    except Exception as e:
        st.error(f"An unexpected error occurred during GitHub operation: {e}")
        logger.error(f"Failed to update/create file '{file_path}' in '{repo.full_name}': {e}", exc_info=True)
        return False


# --- STREAMLIT APP UTAMA ---

st.set_page_config(page_title="Sing-Box Config Converter & Uploader", page_icon="⚙️", layout="centered")

st.title("Sing-Box VPN Config Modifier")
st.markdown("Masukkan Link VPN (VMess/VLESS/Trojan) untuk memodifikasi konfigurasi Sing-Box dari template.")

# --- Ambil Secrets/Environment Variables ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN_VPN_BOT")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
DEFAULT_TARGET_REPO = os.environ.get("DEFAULT_TARGET_REPO", "") 

# --- Bagian Admin Access ---
is_admin = False
if ADMIN_PASSWORD:
    st.sidebar.header("Admin Access")
    password_input = st.sidebar.text_input("Enter Admin Password", type="password")
    if password_input == ADMIN_PASSWORD:
        is_admin = True
        st.sidebar.success("Admin access granted!")
    elif password_input:
        st.sidebar.error("Incorrect password.")
else:
    st.warning("ADMIN_PASSWORD is not set in Streamlit Secrets. GitHub upload features will be disabled.")
    st.sidebar.info("Untuk mengaktifkan fitur upload, set ADMIN_PASSWORD di Streamlit Secrets.")

# --- Inisialisasi GitHub API ---
github_client = None
if GITHUB_TOKEN:
    try:
        github_client = Github(GITHUB_TOKEN)
    except Exception as e:
        st.sidebar.error(f"Error initializing GitHub client: {e}. Pastikan GITHUB_TOKEN_VPN_BOT valid.")
        logger.error(f"Error initializing GitHub client: {e}", exc_info=True)
else:
    st.warning("GITHUB_TOKEN_VPN_BOT is not set in Streamlit Secrets. GitHub upload feature will be disabled.")


# --- Input VPN Link ---
vpn_link_input = st.text_area("Masukkan Link VPN (VMess/VLESS/Trojan):", height=150)

# Path ke file template, hardcoded karena singbox_converter.py sekarang membacanya dari file
template_file_path = "singbox-template.txt"

convert_button = st.button("Modifikasi Sing-Box Config")

converted_config_content = ""
new_outbound_tag_display = ""

if convert_button:
    if not vpn_link_input:
        st.error("Link VPN tidak boleh kosong!")
    else:
        try:
            # Panggil fungsi konversi dari singbox_converter.py
            # Sekarang hanya perlu vpn_link_input dan path ke template file
            result = process_singbox_config(vpn_link_input, template_file_path) 
            
            if result["status"] == "success":
                converted_config_content = result["config_content"]
                new_outbound_tag_display = result.get("new_outbound_tag", "N/A")
                st.subheader(f"✅ Konfigurasi Sing-Box Berhasil Dimodifikasi!")
                st.info(f"Outbound baru dengan tag: `{new_outbound_tag_display}` telah ditambahkan dan selektor diperbarui.")
                st.code(converted_config_content, language="json")

                # --- DOWNLOAD BUTTON ---
                st.download_button(
                    label="Download Config",
                    data=converted_config_content,
                    file_name="singbox_modified_config.json",
                    mime="application/json"
                )

            else:
                st.error(f"❌ Error Modifikasi: {result['message']}")
                logger.error(f"Conversion error: {result['message']}")
        except Exception as e:
            st.error(f"❌ Terjadi error tak terduga: {e}")
            logger.error(f"Unexpected error in app.py: {e}", exc_info=True)


# --- Bagian Admin untuk Upload GitHub ---
if is_admin and github_client and converted_config_content:
    st.markdown("---")
    st.subheader("Upload Config ke GitHub (Admin Only)")

    target_repo_full_name = st.text_input(
        "Masukkan Nama Repositori Target (contoh: 'NamaUser/NamaRepo'):",
        value=DEFAULT_TARGET_REPO
    )

    # Menghapus pilihan "Path lain..." karena sekarang fokus ke satu template output
    # Jika lo mau opsi untuk output ke file lain, kita perlu tambahin logikanya di sini
    selected_github_file_path = st.text_input(
        "Path file di repositori target (contoh: 'configs/singbox.json'):",
        value="singbox.json", # Default ke singbox.json
        help="Ini adalah path file di repositori GitHub lo yang akan diupdate/dibuat."
    )

    commit_message = st.text_input(
        "Pesan Commit untuk GitHub:",
        value=f"Update {selected_github_file_path} via Streamlit app (New Outbound: {new_outbound_tag_display})"
    )

    upload_github_button = st.button(f"Upload '{selected_github_file_path}' ke GitHub")

    if upload_github_button:
        if not target_repo_full_name:
            st.error("Nama repositori target tidak boleh kosong!")
        elif not selected_github_file_path:
            st.error("Path file GitHub tidak boleh kosong!")
        else:
            try:
                target_repo = github_client.get_repo(target_repo_full_name)
                
                if update_github_file(target_repo, selected_github_file_path, converted_config_content, commit_message):
                    st.success("Konfigurasi berhasil diupload ke GitHub!")
                else:
                    st.error("Gagal mengupload konfigurasi ke GitHub. Cek log atau izin token.")
            except Exception as e:
                st.error(f"Error mengakses repositori '{target_repo_full_name}': {e}. Pastikan nama repo benar dan token memiliki izin.")
                logger.error(f"Error getting target repo '{target_repo_full_name}': {e}", exc_info=True)

elif is_admin and not github_client:
    st.warning("Admin: GitHub token belum diset atau ada masalah saat inisialisasi. Fitur upload tidak aktif.")
elif is_admin and not converted_config_content:
    st.info("Admin: Modifikasi config dulu sebelum bisa mengupload ke GitHub.")
elif not is_admin:
    st.info("Login sebagai Admin di sidebar untuk mengupload konfigurasi ke GitHub.")

st.markdown("---")
st.caption("Dibuat dengan 🔥 oleh teman lo.")
