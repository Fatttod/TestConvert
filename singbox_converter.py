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

# --- MAPPING KODE NEGARA KE EMOJI BENDERA ---
COUNTRY_CODE_TO_EMOJI = {
    "US": "🇺🇸", "SG": "🇸🇬", "DE": "🇩🇪", "FR": "🇫🇷", "NL": "🇳🇱",
    "GB": "🇬🇧", "CA": "🇨🇦", "AU": "🇦🇺", "JP": "🇯🇵", "KR": "🇰🇷",
    "HK": "🇭🇰", "TW": "🇹🇼", "IN": "🇮🇳", "ID": "🇮🇩", "BR": "🇧🇷",
    "RU": "🇷🇺", "CH": "🇨🇭", "SE": "🇸🇪", "FI": "🇫🇮", "NO": "🇳🇴",
    "DK": "🇩🇰", "IE": "🇮🇪", "IT": "🇮🇹", "ES": "🇪🇸", "PT": "🇵🇹",
    "PL": "🇵🇱", "CZ": "🇨🇿", "HU": "🇭🇺", "AT": "🇦🇹", "BE": "🇧🇪",
    "GR": "🇬🇷", "IL": "🇮🇱", "AE": "🇦🇪", "SA": "🇸🇦", "ZA": "🇿🇦",
    "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱", "PE": "🇵🇪", "CO": "🇨🇴",
    "VE": "🇻🇪", "MY": "🇲🇾", "TH": "🇹🇭", "VN": "🇻🇳", "PH": "🇵🇭",
    "NZ": "🇳🇿", "EG": "🇪🇬", "TR": "🇹🇷", "UA": "🇺🇦", "NG": "🇳🇬",
    # Tambahkan lebih banyak jika diperlukan
}

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
                
                base_tag = f"vmess-{parsed_data.get('add', 'NoName')}"
                display_name_from_link = parsed_data.get('ps', '')

                new_outbound_object = {
                    "type": "vmess",
                    "tag": base_tag, # Akan di-update di bawah
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
                
                # Logic untuk tag VMess (mirip Trojan)
                if display_name_from_link:
                    country_code_match = re.match(r'^\s*\(?([A-Za-z]{2})\)?\s*(.*)', display_name_from_link)
                    
                    country_emoji = ""
                    remaining_name = display_name_from_link

                    if country_code_match:
                        code = country_code_match.group(1).upper()
                        if code in COUNTRY_CODE_TO_EMOJI:
                            country_emoji = COUNTRY_CODE_TO_EMOJI[code]
                            remaining_name = country_code_match.group(2).strip()
                            if remaining_name.startswith('(') and remaining_name.endswith(')'):
                                remaining_name = remaining_name[1:-1].strip()

                    cleaned_remaining_name = re.sub(r'[^\w\s\-\(\)\[\]]+', '', remaining_name) 
                    cleaned_remaining_name = cleaned_remaining_name.strip().replace(" ", "-").replace("--", "-") 
                    
                    if country_emoji and cleaned_remaining_name:
                        new_outbound_object["tag"] = f"{base_tag} {country_emoji} {cleaned_remaining_name}"
                    elif country_emoji:
                        new_outbound_object["tag"] = f"{base_tag} {country_emoji}"
                    elif cleaned_remaining_name:
                        new_outbound_object["tag"] = f"{base_tag}-{cleaned_remaining_name}"
                    else:
                        new_outbound_object["tag"] = base_tag
                else:
                    new_outbound_object["tag"] = base_tag
                
                new_outbound_object["tag"] = new_outbound_object["tag"].replace("  ", " ").strip().replace(" ", "-")
                new_outbound_tag = new_outbound_object["tag"]


        elif "vless://" in vpn_link:
            parsed_data = parse_vless_link(vpn_link)
            if parsed_data:
                protocol_type = "vless"
                
                base_tag = f"vless-{parsed_data.get('address', 'NoName')}"
                # Asumsi VLESS link tidak selalu punya 'ps' atau display name di query param
                # Jika ada 'ps' di query param VLESS, perlu penyesuaian di parse_vless_link
                # Untuk saat ini, kita bisa coba ekstrak dari 'sni' atau 'host' jika itu merepresentasikan nama
                display_name_from_link = parsed_data.get('sni') or parsed_data.get('host') or ""

                new_outbound_object = {
                    "type": "vless",
                    "tag": base_tag, # Akan di-update di bawah
                    "server": parsed_data.get('address', ''),
                    "server_port": parsed_data.get('port', 443),
                    "uuid": parsed_data.get('uuid', ''),
                    "flow": parsed_data.get('flow'),
                    "network": parsed_data.get('type', 'tcp'),
                    "tls": parsed_data.get('security', '') == 'tls' or parsed_data.get('security', '') == 'reality',
                    "reality": parsed_data.get('security', '') == 'reality',
                    "xudp": True,
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
                
                # Logic untuk tag VLESS
                if display_name_from_link:
                    country_code_match = re.match(r'^\s*\(?([A-Za-z]{2})\)?\s*(.*)', display_name_from_link)
                    
                    country_emoji = ""
                    remaining_name = display_name_from_link

                    if country_code_match:
                        code = country_code_match.group(1).upper()
                        if code in COUNTRY_CODE_TO_EMOJI:
                            country_emoji = COUNTRY_CODE_TO_EMOJI[code]
                            remaining_name = country_code_match.group(2).strip()
                            if remaining_name.startswith('(') and remaining_name.endswith(')'):
                                remaining_name = remaining_name[1:-1].strip()

                    cleaned_remaining_name = re.sub(r'[^\w\s\-\(\)\[\]]+', '', remaining_name) 
                    cleaned_remaining_name = cleaned_remaining_name.strip().replace(" ", "-").replace("--", "-") 
                    
                    if country_emoji and cleaned_remaining_name:
                        new_outbound_object["tag"] = f"{base_tag} {country_emoji} {cleaned_remaining_name}"
                    elif country_emoji:
                        new_outbound_object["tag"] = f"{base_tag} {country_emoji}"
                    elif cleaned_remaining_name:
                        new_outbound_object["tag"] = f"{base_tag}-{cleaned_remaining_name}"
                    else:
                        new_outbound_object["tag"] = base_tag
                else:
                    new_outbound_object["tag"] = base_tag
                
                new_outbound_object["tag"] = new_outbound_object["tag"].replace("  ", " ").strip().replace(" ", "-")
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
                    # 1. Pisahkan nama dan kode negara
                    country_code_match = re.match(r'^\s*\(?([A-Za-z]{2})\)?\s*(.*)', display_name_from_path)
                    
                    country_emoji = ""
                    remaining_name = display_name_from_path

                    if country_code_match:
                        code = country_code_match.group(1).upper()
                        if code in COUNTRY_CODE_TO_EMOJI:
                            country_emoji = COUNTRY_CODE_TO_EMOJI[code]
                            remaining_name = country_code_match.group(2).strip() # Sisa string setelah kode negara
                            
                            # Jika ada tanda kurung di sekitar kode negara, hapus dari remaining_name jika masih ada
                            # Ini untuk kasus "(SG) DigitalOcean" -> remaining_name jadi "DigitalOcean"
                            # atau "SG DigitalOcean" -> remaining_name jadi "DigitalOcean"
                            # Tapi ini nggak dipakai kalau kode negara sudah berhasil di-parse dan dipisah
                            # remaining_name = remaining_name.strip() # Pastikan tidak ada spasi di awal/akhir
                            
                            # Hapus tanda kutip jika ada di awal/akhir remaining_name
                            if remaining_name.startswith('"') and remaining_name.endswith('"'):
                                remaining_name = remaining_name[1:-1].strip()


                    # 2. Bersihkan remaining_name
                    # Hapus karakter non-alphanumeric, spasi, dan beberapa simbol yang aman untuk tag
                    cleaned_remaining_name = re.sub(r'[^\w\s\-\(\)\[\]]+', '', remaining_name) 
                    # Ganti spasi dengan strip, dan hapus strip ganda
                    cleaned_remaining_name = cleaned_remaining_name.strip().replace(" ", "-").replace("--", "-") 
                    
                    # Gabungkan emoji dan nama bersih
                    if country_emoji and cleaned_remaining_name:
                        new_outbound_object["tag"] = f"{base_tag} {country_emoji} {cleaned_remaining_name}"
                    elif country_emoji:
                        new_outbound_object["tag"] = f"{base_tag} {country_emoji}"
                    elif cleaned_remaining_name:
                        new_outbound_object["tag"] = f"{base_tag}-{cleaned_remaining_name}"
                    else:
                        new_outbound_object["tag"] = base_tag # Fallback jika tidak ada info tambahan
                    
                    # Final cleanup of tag for spaces and potential double dashes
                    new_outbound_object["tag"] = new_outbound_object["tag"].replace("  ", " ").strip().replace(" ", "-")
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
            
