import streamlit as st
import os
import sys
import logging

from github import Github, GithubException
# Import fungsi konversi dari file terpisah
from singbox_converter import process_singbox_config # Panggil fungsi ini

# --- KONFIGURASI LOGGING ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- FUNGSI UPDATE GITHUB FILE (Ini tetap di app.py karena butuh objek Github client) ---
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

st.set_page_config(page_title="Sing-Box Config Updater", page_icon="⚙️", layout="centered")

st.title("Sing-Box VPN Config Converter & GitHub Updater")
st.markdown("Masukkan link VPN (VMess/VLESS/Trojan) dan konversi ke format Sing-Box.")

# --- Ambil Secrets/Environment Variables ---
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN_VPN_BOT")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
DEFAULT_TARGET_REPO = os.environ.get("DEFAULT_TARGET_REPO", "Fatttod/Temempik") 

# --- Bagian Admin Access ---
is_admin = False
if ADMIN_PASSWORD:
    st.sidebar.header("Admin Access")
    password_input = st.sidebar.text_input("Enter Admin Password", type="password")
    if password_input == ADMIN_PASSWORD:
        is_admin = True
        st.sidebar.success("Admin access granted!")
    elif password_input: # Kalau input tapi salah
        st.sidebar.error("Incorrect password.")
else:
    st.warning("ADMIN_PASSWORD is not set in Streamlit Secrets. Upload features will be disabled.")
    st.sidebar.info("Untuk mengaktifkan fitur update, set ADMIN_PASSWORD di Streamlit Secrets.")

# --- Inisialisasi GitHub API ---
github_client = None
if GITHUB_TOKEN:
    try:
        github_client = Github(GITHUB_TOKEN)
    except Exception as e:
        st.sidebar.error(f"Error initializing GitHub client: {e}. Pastikan GITHUB_TOKEN_VPN_BOT valid.")
        logger.error(f"Error initializing GitHub client: {e}", exc_info=True)
else:
    st.warning("GITHUB_TOKEN_VPN_BOT is not set in Streamlit Secrets. GitHub update feature will be disabled.")


# --- Input VPN Link ---
vpn_link_input = st.text_area("Masukkan Link VPN (VMess/VLESS/Trojan):", height=150)
convert_button = st.button("Konversi ke Sing-Box Config")

converted_config_content = ""
if convert_button and vpn_link_input:
    # Panggil fungsi konversi dari singbox_converter.py
    result = process_singbox_config(vpn_link_input) 
    
    if result["status"] == "success":
        converted_config_content = result["config_content"]
        st.subheader("Hasil Konversi Sing-Box Config:")
        st.code(converted_config_content, language="json")
    else:
        st.error(f"❌ Error konversi: {result['message']}")
        logger.error(f"Conversion error: {result['message']}")


# --- Bagian Admin untuk Update GitHub ---
if is_admin and github_client and converted_config_content: # Pastikan ada config yang sudah dikonversi
    st.markdown("---")
    st.subheader("Update GitHub Config (Admin Only)")

    # Input untuk nama repositori target (defaultnya yang lo kasih tadi)
    target_repo_full_name = st.text_input(
        "Masukkan Nama Repositori Target (contoh: 'Fatttod/Temempik'):",
        value=DEFAULT_TARGET_REPO
    )

    # Pilihan file yang ingin diupdate
    selected_github_file = st.radio(
        "Pilih file di repositori target yang ingin diupdate:",
        ("sfa.txt", "tsel-sfa.txt")
    )

    commit_message = st.text_input(
        "Pesan Commit untuk GitHub:",
        value=f"Update {selected_github_file} via Streamlit app"
    )

    update_github_button = st.button(f"Update '{selected_github_file}' di GitHub")

    if update_github_button:
        if not target_repo_full_name:
            st.error("Nama repositori target tidak boleh kosong!")
        else:
            try:
                target_repo = github_client.get_repo(target_repo_full_name)
                
                if update_github_file(target_repo, selected_github_file, converted_config_content, commit_message):
                    st.success("Konfigurasi berhasil diupdate ke GitHub!")
                else:
                    st.error("Gagal mengupdate konfigurasi ke GitHub. Cek log atau izin token.")
            except Exception as e:
                st.error(f"Error mengakses repositori '{target_repo_full_name}': {e}. Pastikan nama repo benar dan token memiliki izin.")
                logger.error(f"Error getting target repo '{target_repo_full_name}': {e}", exc_info=True)

elif is_admin and not github_client:
    st.warning("Admin: GitHub token belum diset atau ada masalah saat inisialisasi. Fitur update tidak aktif.")
elif is_admin and not converted_config_content:
    st.info("Admin: Konversi link VPN dulu sebelum bisa mengupdate ke GitHub.")
elif not is_admin:
    st.info("Login sebagai Admin di sidebar untuk mengupdate konfigurasi ke GitHub.")

st.markdown("---")
st.caption("Dibuat dengan 🔥 oleh teman lo.")
  
