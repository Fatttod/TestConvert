import json
import os
import urllib.parse
import base64
import re
import logging
import sys

# --- KONFIGURASI LOGGING ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO,
                    stream=sys.stdout)
logger = logging.getLogger(__name__)

# --- FUNGSI PARSING LINK VPN (LENGKAP DENGAN VMESS, VLESS, TROJAN) ---

def parse_vmess_link(vmess_link):
    try:
        if not vmess_link or not vmess_link.startswith("vmess://"):
            logger.debug(f"VMess link invalid format or empty: {vmess_link[:50]}...")
            return None
        
        encoded_data = vmess_link[len("vmess://"):]
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)

        decoded_data = base64.b64decode(encoded_data).decode('utf-8')
        config = json.loads(decoded_data)
        logger.debug(f"Successfully parsed VMess link: {config.get('ps', 'NoName')}")
        return config
    except Exception as e:
        logger.error(f"Error parsing VMess link (base64/JSON issue) for {vmess_link[:50]}...: {e}")
        return None

def parse_vless_link(vless_link):
    try:
        if not vless_link or not vless_link.startswith("vless://"):
            logger.debug(f"VLESS link invalid format or empty: {vless_link[:50]}...")
            return None
        
        parts = vless_link[len("vless://"):].split('@', 1)
        if len(parts) != 2:
            return None
        
        user_info = parts[0] # UUID
        host_port_query = parts[1]
        
        host_parts = host_port_query.split('?', 1)
        host_port = host_parts[0]
        query_params = {}
        if len(host_parts) == 2:
            query_params = urllib.parse.parse_qs(host_parts[1])

        host, port = (host_port.split(':') + ['443'])[:2] # Default to 443 if port missing

        config = {
            "uuid": user_info,
            "address": host,
            "port": int(port),
            "security": query_params.get('security', ['none'])[0],
            "type": query_params.get('type', ['tcp'])[0],
            "headerType": query_params.get('headerType', ['none'])[0],
            "host": query_params.get('host', [''])[0],
            "path": query_params.get('path', [''])[0],
            "sni": query_params.get('sni', [''])[0],
            "alpn": query_params.get('alpn', [''])[0],
            "fp": query_params.get('fp', [''])[0], # flow fingerprint
            "flow": query_params.get('flow', [''])[0] # for XTLS
        }
        
        for key in ["host", "path", "sni", "alpn", "fp", "flow"]:
            if config[key] == '':
                config[key] = None
        
        logger.debug(f"Successfully parsed VLESS link: {host}")
        return config
    except Exception as e:
        logger.error(f"Error parsing VLESS link for {vless_link[:50]}...: {e}")
        return None

def parse_trojan_link(trojan_link):
    try:
        if not trojan_link or not trojan_link.startswith("trojan://"):
            logger.debug(f"Trojan link invalid format or empty: {trojan_link[:50]}...")
            return None

        parts = trojan_link[len("trojan://"):].split('@', 1)
        if len(parts) != 2:
            return None
        
        password = parts[0]
        host_port_query = parts[1]

        host_parts = host_port_query.split('?', 1)
        host_port = host_parts[0]
        query_params = {}
        if len(host_parts) == 2:
            query_params = urllib.parse.parse_qs(host_parts[1])

        host, port = (host_port.split(':') + ['443'])[:2] # Default to 443 if port missing

        config = {
            "password": password,
            "address": host,
            "port": int(port),
            "security": query_params.get('security', ['tls'])[0], # Trojan default security is tls
            "type": query_params.get('type', ['tcp'])[0],
            "sni": query_params.get('sni', [''])[0],
            "alpn": query_params.get('alpn', [''])[0],
            "fp": query_params.get('fp', [''])[0], # flow fingerprint
            "flow": query_params.get('flow', [''])[0] # for XTLS
        }
        
        for key in ["sni", "alpn", "fp", "flow"]:
            if config[key] == '':
                config[key] = None

        # Tambahkan host dan path untuk websocket/http (ini yang perlu diperhatikan khusus)
        # Note: 'host' di query_params bisa jadi websocket_headers Host
        # 'path' di query_params bisa jadi websocket_path
        config['host'] = query_params.get('host', [''])[0] 
        config['path'] = query_params.get('path', [''])[0]

        logger.debug(f"Successfully parsed Trojan link: {host}")
        return config
    except Exception as e:
        logger.error(f"Error parsing Trojan link for {trojan_link[:50]}...: {e}")
        return None

# --- FUNGSI UTAMA KONVERSI & MODIFIKASI CONFIG (Sesuai keinginan lo, Tod!) ---
def process_singbox_config(vpn_link, template_file_path="singbox-template.txt"):
    # List tag selektor yang TIDAK boleh diotak-atik
    TAGS_TO_SKIP = {
        "WhatsApp",
        "GAMESMAX(ML/FF/AOV)",
        "Route Port Game",
        "Option ADs",
        "Option P0rn"
    }

    try:
        # 1. Parse link VPN menjadi outbound object yang siap ditambahkan
        new_outbound_object = {}
        new_outbound_tag = ""
        protocol_type = None

        if "vmess://" in vpn_link:
            parsed_data = parse_vmess_link(vpn_link)
            if parsed_data:
                protocol_type = "vmess"
                # Bentuk outbound object sesuai format Sing-Box dari VMess
                new_outbound_object = {
                    "type": "vmess",
                    "tag": f"vmess-{parsed_data.get('ps', 'NoName')}",
                    "server": parsed_data.get('add', ''),
                    "server_port": int(parsed_data.get('port', 443)),
                    "uuid": parsed_data.get('id', ''),
                    "alter_id": int(parsed_data.get('aid', 0)),
                    "security": parsed_data.get('scy', 'auto'),
                    "network": parsed_data.get('net', 'tcp'),
                    "tls": parsed_data.get('tls', '') == 'tls',
                }
                if new_outbound_object["tls"]:
                    new_outbound_object["tls_sni"] = parsed_data.get('sni', parsed_data.get('host', ''))
                
                if new_outbound_object["network"] == "ws":
                    new_outbound_object["websocket_path"] = parsed_data.get('path', '/')
                    if parsed_data.get('host'):
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('host', '')}
                
                new_outbound_tag = new_outbound_object["tag"]

        elif "vless://" in vpn_link:
            parsed_data = parse_vless_link(vpn_link)
            if parsed_data:
                protocol_type = "vless"
                # Bentuk outbound object sesuai format Sing-Box dari VLESS
                new_outbound_object = {
                    "type": "vless",
                    "tag": f"vless-{parsed_data.get('address', 'NoName')}", # Tag bisa disesuaikan
                    "server": parsed_data.get('address', ''),
                    "server_port": parsed_data.get('port', 443),
                    "uuid": parsed_data.get('uuid', ''),
                    "flow": parsed_data.get('flow'),
                    "network": parsed_data.get('type', 'tcp'),
                    "tls": parsed_data.get('security', '') == 'tls' or parsed_data.get('security', '') == 'reality', # VLESS bisa TLS atau Reality
                    "reality": parsed_data.get('security', '') == 'reality', # Tambahkan reality jika ada
                    "xudp": True, # Asumsi default
                }
                if new_outbound_object["tls"] or new_outbound_object["reality"]:
                    if parsed_data.get('sni'):
                        new_outbound_object["tls_sni"] = parsed_data.get('sni')
                    if parsed_data.get('fp'):
                        new_outbound_object["tls_fingerprint"] = parsed_data.get('fp')
                    if parsed_data.get('alpn'):
                        new_outbound_object["tls_alpn"] = [parsed_data.get('alpn')]
                
                if new_outbound_object["network"] == "ws":
                    new_outbound_object["websocket_path"] = parsed_data.get('path', '/')
                    if parsed_data.get('host'):
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('host', '')}
                
                new_outbound_tag = new_outbound_object["tag"]

        elif "trojan://" in vpn_link:
            parsed_data = parse_trojan_link(vpn_link)
            if parsed_data:
                protocol_type = "trojan"
                
                # Inisialisasi tag dasar
                base_tag = f"trojan-{parsed_data.get('address', 'NoName')}"
                
                # Ambil path asli dari parsed_data
                full_path_from_param = parsed_data.get('path', '/')
                actual_websocket_path = "/" # Default jika tidak ada path
                display_name_from_path = ""

                # Cek apakah path mengandung '#' yang menandakan adanya display name
                if '#' in full_path_from_param:
                    path_parts = full_path_from_param.split('#', 1)
                    actual_websocket_path = path_parts[0]
                    display_name_from_path = path_parts[1].strip()
                else:
                    actual_websocket_path = full_path_from_param # Jika tidak ada '#', seluruhnya adalah path

                # Bentuk outbound object sesuai format Sing-Box dari Trojan
                new_outbound_object = {
                    "type": "trojan",
                    "tag": base_tag, # Akan diperbarui di bawah
                    "server": parsed_data.get('address', ''),
                    "server_port": parsed_data.get('port', 443),
                    "password": parsed_data.get('password', ''),
                    "flow": parsed_data.get('flow'),
                    "network": parsed_data.get('type', 'tcp'),
                    "tls": True, # Trojan selalu TLS
                    "xudp": True, # Asumsi default
                }
                
                if new_outbound_object["tls"]:
                    if parsed_data.get('sni'):
                        new_outbound_object["tls_sni"] = parsed_data.get('sni')
                    if parsed_data.get('fp'):
                        new_outbound_object["tls_fingerprint"] = parsed_data.get('fp')
                    if parsed_data.get('alpn'):
                        new_outbound_object["tls_alpn"] = [parsed_data.get('alpn')]
                
                if new_outbound_object["network"] == "ws":
                    new_outbound_object["websocket_path"] = actual_websocket_path
                    if parsed_data.get('host'):
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('host', '')}
                
                # Perbarui tag dengan display_name_from_path jika ada
                if display_name_from_path:
                    # Bersihkan display_name_from_path agar cocok untuk tag
                    cleaned_display_name = re.sub(r'[^\w\s\-\(\)\[\]]+', '', display_name_from_path) # Hapus karakter selain alfanum, spasi, -, (), [], biar tag bersih
                    cleaned_display_name = cleaned_display_name.strip().replace(" ", "-") # Ganti spasi dengan strip
                    
                    if cleaned_display_name: # Pastikan hasilnya tidak kosong
                        new_outbound_object["tag"] = f"{base_tag}-{cleaned_display_name}"
                    else:
                        new_outbound_object["tag"] = base_tag
                
                new_outbound_tag = new_outbound_object["tag"]
        else:
            return {"status": "error", "message": "Tipe link VPN tidak didukung. Hanya VMess, VLESS, atau Trojan."}
        
        if not new_outbound_object:
            return {"status": "error", "message": f"Gagal memparse link VPN ({protocol_type}). Cek formatnya."}

        # Hapus kunci dengan nilai None atau string kosong jika tidak relevan untuk Sing-Box
        keys_to_remove = []
        for key, value in new_outbound_object.items():
            if value is None or (isinstance(value, str) and not value) or (isinstance(value, list) and not value):
                keys_to_remove.append(key)
        for key in keys_to_remove:
            del new_outbound_object[key]


        # 2. Muat konfigurasi dasar Sing-Box dari template file
        try:
            # Menggunakan template_file_path yang diterima sebagai argumen
            with open(template_file_path, 'r') as f:
                config_data = json.load(f)
        except FileNotFoundError:
            return {"status": "error", "message": f"File template Sing-Box '{template_file_path}' tidak ditemukan."}
        except json.JSONDecodeError as e:
            return {"status": "error", "message": f"Format JSON di file template '{template_file_path}' tidak valid: {e}"}
        except Exception as e:
            return {"status": "error", "message": f"Error memuat file template '{template_file_path}': {e}"}

        # Pastikan ada bagian "outbounds"
        if "outbounds" not in config_data or not isinstance(config_data["outbounds"], list):
            return {"status": "error", "message": "Konfigurasi dasar tidak memiliki array 'outbounds' yang valid."}

        # 3. Tambahkan outbound baru ke daftar outbounds utama
        # Cek duplikasi tag sebelum menambahkan
        existing_tags = {out.get("tag") for out in config_data["outbounds"] if isinstance(out, dict) and "tag" in out}
        if new_outbound_tag in existing_tags:
            # Jika tag sudah ada, tambahkan suffix angka untuk menghindari konflik
            suffix = 1
            original_tag_base = new_outbound_tag
            # Hapus suffix angka jika sudah ada sebelumnya untuk mencari base tag
            original_tag_base = re.sub(r'-\d+$', '', original_tag_base) 
            while f"{original_tag_base}-{suffix}" in existing_tags:
                suffix += 1
            new_outbound_tag = f"{original_tag_base}-{suffix}"
            new_outbound_object["tag"] = new_outbound_tag
            logger.warning(f"Tag '{original_tag_base}' sudah ada, menggunakan tag baru: '{new_outbound_tag}'")
        
        config_data["outbounds"].append(new_outbound_object)
        logger.info(f"Outbound baru dengan tag '{new_outbound_tag}' berhasil ditambahkan ke daftar utama.")

        # 4. Perbarui outbounds di selektor dan urltest (SESUAI LOGIKA LO YANG SPESIFIK & PENGECUALIAN)
        updated_ref_count = 0
        for outbound_item in config_data["outbounds"]:
            if isinstance(outbound_item, dict) and outbound_item.get("type") in ["selector", "urltest"]:
                current_selector_tag = outbound_item.get("tag", "Unnamed Selector")
                
                # --- Pengecualian: SKIP selektor yang tidak boleh diubah ---
                if current_selector_tag in TAGS_TO_SKIP:
                    logger.debug(f"Skipping modification for selector '{current_selector_tag}' as per user's instruction.")
                    continue # Langsung skip ke item berikutnya

                original_nested_outbounds_list = outbound_item.get("outbounds", [])[:] # Salin list asli
                
                final_nested_outbounds = [] # List untuk menyimpan outbounds yang akan di-set
                
                # Tambahkan new_outbound_tag ke selector "proxy-selector" dan "urltest-selector"
                # Cek apakah 'proxy-selector' ada dalam current_selector_tag atau 'urltest-selector' ada dalam current_selector_tag
                if "proxy-selector" in current_selector_tag or "urltest-selector" in current_selector_tag:
                    final_nested_outbounds.append(new_outbound_tag)
                
                # Salin outbounds yang sudah ada, kecuali yang sama dengan new_outbound_tag (untuk hindari duplikasi)
                for existing_tag_in_selector in original_nested_outbounds_list:
                    if existing_tag_in_selector != new_outbound_tag:
                        final_nested_outbounds.append(existing_tag_in_selector)
                
                # Tambahkan 'direct' ke 'auto-selector' dan 'urltest-selector' jika belum ada
                if current_selector_tag in ["auto-selector", "urltest-selector"]:
                    if "direct" not in final_nested_outbounds:
                        final_nested_outbounds.append("direct")

                # Tambahkan 'proxy' ke 'auto-selector' dan 'urltest-selector' jika belum ada
                if current_selector_tag in ["auto-selector", "urltest-selector"]:
                    if "proxy" not in final_nested_outbounds:
                        final_nested_outbounds.append("proxy")
                
                # Proses deduplikasi dan pertahankan urutan
                seen = set()
                deduplicated_list = []
                for x in final_nested_outbounds:
                    if x not in seen:
                        deduplicated_list.append(x)
                        seen.add(x)
                
                final_nested_outbounds = deduplicated_list

                # Hanya update jika ada perubahan pada list outbounds nested
                if final_nested_outbounds != original_nested_outbounds_list:
                    outbound_item["outbounds"] = final_nested_outbounds
                    updated_ref_count += 1
                    logger.debug(f"Updated selector '{current_selector_tag}'. New outbounds: {final_nested_outbounds}")
                else:
                    logger.debug(f"Selector '{current_selector_tag}' not updated (no changes).")
            else:
                logger.debug(f"Skipping non-selector item or malformed selector: {outbound_item.get('tag', 'No Tag')} (Type: {type(outbound_item)})\nContent: {outbound_item}")


        logger.info(f"{updated_ref_count} selektor/urltest outbounds berhasil diperbarui referensinya.")

        # 5. Dump objek JSON yang sudah di-update menjadi string JSON
        new_config_content = json.dumps(config_data, indent=2)
        
        return {
            "status": "success", 
            "message": "Konfigurasi Sing-Box baru sudah dibuat dan selektor diperbarui.",
            "config_content": new_config_content, 
            "new_outbound_tag": new_outbound_tag 
        }

    except Exception as e:
        logger.error(f"Error during Sing-Box conversion: {e}", exc_info=True)
        return {"status": "error", "message": f"Terjadi error yang nggak terduga saat konversi Sing-Box: {e}"}

if __name__ == '__main__':
    pass # Ini cuma buat debugging lokal singbox_converter.py secara terpisah
              
