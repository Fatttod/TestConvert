# singbox_converter.py (Revisi untuk format TAG yang lebih spesifik, perbaikan kurung, dan penanganan WebSocket)
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

# --- FUNGSI HELPER UNTUK MEMBERSIHKAN DAN MEMBENTUK TAG ---
def _clean_and_tag_name(display_name, link_type, server_address, index):
    """
    Cleans a display name from a VPN link and generates a user-friendly tag
    with format: [bendera negara] [Nama ISP/Provider] [Nomor Urut Konversi]
    """
    country_emoji = ""
    isp_name = ""
    
    # 1. Coba deteksi bendera dari display_name atau server_address
    country_match = re.search(r'\(?\s*([A-Za-z]{2})\s*\)?', display_name)
    if not country_match:
        country_match = re.search(r'([A-Za-z]{2})$', display_name)
    if not country_match:
        country_match = re.match(r'^\s*([A-Za-z]{2})\s*', display_name)

    if country_match:
        code = country_match.group(1).upper()
        if code in COUNTRY_CODE_TO_EMOJI:
            country_emoji = COUNTRY_CODE_TO_EMOJI[code]
            display_name = re.sub(r'\(?\s*'+re.escape(country_match.group(0))+r'\s*\)?', '', display_name, flags=re.IGNORECASE).strip()
    
    # 2. Ekstrak Nama ISP/Provider
    cleaned_name = re.sub(r'^(.*?\.com|.*?\.net|.*?\.org|.*?\.io|.*?\.xyz|.*?\.me|.*?\.link|.*?\.cloud|.*?\.fun|.*?\.online|.*?\.icu|vpn|server|node|proxy|free|vip|premium|test|trial|fast|speed|best|gaming|sgp|id|us|de|fr|nl|gb|ca|au|jp|kr|hk|tw|in|br|ru|ch|se|fi|no|dk|ie|it|es|pt|pl|cz|hu|at|be|gr|il|ae|sa|za|mx|ar|cl|pe|co|ve|my|th|vn|ph|nz|eg|tr|ua|ng|singapore|indonesia|united-states|germany|france|netherlands|united-kingdom|canada|australia|japan|korea|hongkong|taiwan|india|brazil|russia|switzerland|sweden|finland|norway|denmark|ireland|italy|spain|portugal|poland|czech|hungary|austria|belgium|greece|israel|uae|saudi|southafrica|mexico|argentina|chile|peru|colombia|venezuela|malaysia|thailand|vietnam|philippines|newzealand|egypt|turkey|ukraine|nigeria)-*', '', display_name, flags=re.IGNORECASE)
    cleaned_name = re.sub(r'[^\w\s\-\(\)\[\]]+', '', cleaned_name)
    cleaned_name = cleaned_name.strip().replace(" ", "-").replace("--", "-")
    
    if not cleaned_name:
        match_domain = re.search(r'([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+)$', server_address)
        if match_domain:
            isp_name = match_domain.group(1).split('.')[0]
            isp_name = isp_name.replace("-", "").strip()
        else:
            isp_name = server_address.replace(".", "-").replace(":", "-").strip()
    else:
        isp_name = cleaned_name

    if not isp_name and server_address:
        domain_match = re.search(r'([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+)$', server_address)
        if domain_match:
            isp_name = domain_match.group(1).split('.')[0]
        else:
            isp_name = server_address.replace('.', '-').replace(':', '-')
    
    if not isp_name:
        isp_name = f"{link_type}-Server"

    index_str = f"{index:02d}"

    final_tag_parts = []
    if country_emoji:
        final_tag_parts.append(country_emoji)
    
    final_tag_parts.append(isp_name)
    final_tag_parts.append(index_str)

    final_tag = " ".join(final_tag_parts).strip()
    
    final_tag = re.sub(r'\s+', ' ', final_tag).strip()
    final_tag = re.sub(r'[-_]+', '-', final_tag).strip('-')
    
    return final_tag.strip()

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

        host, port = (host_port.split(':') + ['443'])[:2]

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
            "fp": query_params.get('fp', [''])[0],
            "flow": query_params.get('flow', [''])[0]
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

        host, port = (host_port.split(':') + ['443'])[:2]

        config = {
            "password": password,
            "address": host,
            "port": int(port),
            "security": query_params.get('security', ['tls'])[0],
            # Menggunakan 'type' dari query_params jika ada, default ke 'tcp'
            "type": query_params.get('type', ['tcp'])[0], 
            "sni": query_params.get('sni', [''])[0],
            "alpn": query_params.get('alpn', [''])[0],
            "fp": query_params.get('fp', [''])[0],
            "flow": query_params.get('flow', [''])[0]
        }
        
        for key in ["sni", "alpn", "fp", "flow"]:
            if config[key] == '':
                config[key] = None

        config['host'] = query_params.get('host', [''])[0] 
        config['path'] = query_params.get('path', [''])[0]

        logger.debug(f"Successfully parsed Trojan link: {host}")
        return config
    except Exception as e:
        logger.error(f"Error parsing Trojan link for {trojan_link[:50]}...: {e}")
        return None

# --- FUNGSI INTERNAL UNTUK MEMPROSES SATU LINK (TIDAK DIPANGGIL LANGSUNG DARI APP.PY) ---
def _process_single_singbox_config(vpn_link, existing_tags, link_index):
    """
    Parses a single VPN link and returns a Sing-Box outbound object and its generated tag.
    Handles tag deduplication internally.
    """
    new_outbound_object = {}
    new_outbound_tag = ""
    protocol_type = None
    server_address_for_tag = ""
    display_name_for_tag = ""

    try:
        if "vmess://" in vpn_link:
            parsed_data = parse_vmess_link(vpn_link)
            if parsed_data:
                protocol_type = "vmess"
                server_address_for_tag = parsed_data.get('add', '')
                display_name_for_tag = parsed_data.get('ps', '')

                new_outbound_object = {
                    "type": "vmess",
                    "tag": "",
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
                
                # --- Penanganan WebSocket untuk VMess ---
                if new_outbound_object["network"] == "ws":
                    new_outbound_object["websocket_path"] = parsed_data.get('path', '/') or '/' # Pastikan tidak kosong
                    if parsed_data.get('host'):
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('host', '')}
                    else: # Fallback jika host kosong, pakai server address
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('add', '')}
                
                new_outbound_tag = _clean_and_tag_name(display_name_for_tag, protocol_type, server_address_for_tag, link_index)

        elif "vless://" in vpn_link:
            parsed_data = parse_vless_link(vpn_link)
            if parsed_data:
                protocol_type = "vless"
                server_address_for_tag = parsed_data.get('address', '')
                display_name_for_tag = parsed_data.get('sni') or parsed_data.get('host') or parsed_data.get('address') or ""

                new_outbound_object = {
                    "type": "vless",
                    "tag": "",
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
                
                # --- Penanganan WebSocket untuk VLESS ---
                if new_outbound_object["network"] == "ws":
                    new_outbound_object["websocket_path"] = parsed_data.get('path', '/') or '/' # Pastikan tidak kosong
                    if parsed_data.get('host'):
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('host', '')}
                    else: # Fallback jika host kosong, pakai server address
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('address', '')}
                
                new_outbound_tag = _clean_and_tag_name(display_name_for_tag, protocol_type, server_address_for_tag, link_index)

        elif "trojan://" in vpn_link:
            parsed_data = parse_trojan_link(vpn_link)
            if parsed_data:
                protocol_type = "trojan"
                server_address_for_tag = parsed_data.get('address', '')
                
                full_path_from_param = parsed_data.get('path', '/')
                actual_websocket_path = "/"
                display_name_from_path = ""

                if '#' in full_path_from_param:
                    path_parts = full_path_from_param.split('#', 1)
                    actual_websocket_path = path_parts[0]
                    display_name_from_path = path_parts[1].strip()
                else:
                    actual_websocket_path = full_path_from_param
                
                display_name_for_tag = display_name_from_path or parsed_data.get('sni') or parsed_data.get('host') or parsed_data.get('address') or ""

                new_outbound_object = {
                    "type": "trojan",
                    "tag": "", 
                    "server": parsed_data.get('address', ''),
                    "server_port": parsed_data.get('port', 443),
                    "password": parsed_data.get('password', ''),
                    "flow": parsed_data.get('flow'),
                    "network": parsed_data.get('type', 'tcp'), # Ambil dari parsed_data, default tcp
                    "tls": True,
                    "xudp": True, 
                }
                
                if new_outbound_object["tls"]:
                    if parsed_data.get('sni'):
                        new_outbound_object["tls_sni"] = parsed_data.get('sni')
                    if parsed_data.get('fp'):
                        new_outbound_object["tls_fingerprint"] = parsed_data.get('fp')
                    if parsed_data.get('alpn'):
                        new_outbound_object["tls_alpn"] = [parsed_data.get('alpn')]
                
                # --- Penanganan WebSocket untuk Trojan ---
                if new_outbound_object["network"] == "ws": # Periksa jika 'network' memang 'ws'
                    new_outbound_object["websocket_path"] = actual_websocket_path or '/' # Pastikan tidak kosong
                    if parsed_data.get('host'):
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('host', '')}
                    else: # Fallback jika host kosong, pakai server address
                        new_outbound_object["websocket_headers"] = {"Host": parsed_data.get('address', '')}
                
                new_outbound_tag = _clean_and_tag_name(display_name_for_tag, protocol_type, server_address_for_tag, link_index)

        else:
            return {"status": "error", "message": "Tipe link VPN tidak didukung. Hanya VMess, VLESS, atau Trojan.", "outbound": None, "tag": None}
        
        if not new_outbound_object:
            return {"status": "error", "message": f"Gagal memparse link VPN ({protocol_type}). Cek formatnya.", "outbound": None, "tag": None}

        keys_to_remove = []
        for key, value in new_outbound_object.items():
            if value is None or (isinstance(value, str) and not value) or (isinstance(value, list) and not value):
                keys_to_remove.append(key)
        for key in keys_to_remove:
            del new_outbound_object[key]

        final_tag = new_outbound_tag
        original_final_tag = final_tag
        suffix_dedup = 1
        while final_tag in existing_tags:
            final_tag = f"{original_final_tag}-{suffix_dedup}"
            suffix_dedup += 1
        
        if final_tag != original_final_tag:
            logger.warning(f"Generated tag '{original_final_tag}' already exists in final config (likely from template). Using '{final_tag}' instead.")
        
        new_outbound_object["tag"] = final_tag
        new_outbound_tag = final_tag

        return {
            "status": "success", 
            "message": "Outbound berhasil diproses.", 
            "outbound": new_outbound_object, 
            "tag": new_outbound_tag
        }

    except Exception as e:
        logger.error(f"Error during single Sing-Box conversion for link {vpn_link[:50]}...: {e}", exc_info=True)
        return {"status": "error", "message": f"Terjadi error saat konversi link {vpn_link[:50]}...: {e}", "outbound": None, "tag": None}


# --- FUNGSI UTAMA UNTUK MEMPROSES BANYAK LINK (INI YANG DIPANGGIL DARI APP.PY) ---
def process_multiple_singbox_configs(vpn_links_list, template_file_path="singbox-template.txt"):
    TAGS_TO_SKIP = {
        "WhatsApp",
        "GAMESMAX(ML/FF/AOV)",
        "Route Port Game",
        "Option ADs",
        "Option P0rn"
    }

    try:
        try:
            with open(template_file_path, 'r') as f:
                config_data = json.load(f)
        except FileNotFoundError:
            return {"status": "error", "message": f"File template Sing-Box '{template_file_path}' tidak ditemukan."}
        except json.JSONDecodeError as e:
            return {"status": "error", "message": f"Format JSON di file template '{template_file_path}' tidak valid: {e}"}
        except Exception as e:
            return {"status": "error", "message": f"Error memuat file template '{template_file_path}': {e}"}

        if "outbounds" not in config_data or not isinstance(config_data["outbounds"], list):
            return {"status": "error", "message": "Konfigurasi dasar tidak memiliki array 'outbounds' yang valid."}

        existing_tags_in_final_config = {out.get("tag") for out in config_data["outbounds"] if isinstance(out, dict) and "tag" in out}
        
        processed_outbound_tags = []
        processed_outbound_objects = []

        for idx, vpn_link in enumerate(vpn_links_list):
            link_result = _process_single_singbox_config(vpn_link, existing_tags_in_final_config, idx + 1)
            
            if link_result["status"] == "success" and link_result["outbound"]:
                new_outbound = link_result["outbound"]
                new_tag = link_result["tag"]
                
                config_data["outbounds"].append(new_outbound)
                existing_tags_in_final_config.add(new_tag)
                processed_outbound_tags.append(new_tag)
                processed_outbound_objects.append(new_outbound)
                logger.info(f"Link {idx+1}: Outbound dengan tag '{new_tag}' berhasil ditambahkan.")
            else:
                logger.warning(f"Link {idx+1}: Gagal memproses link '{vpn_link[:50]}...': {link_result['message']}")

        if not processed_outbound_tags:
            return {"status": "warning", "message": "Tidak ada link VPN yang berhasil diproses. Cek format link lo, Tod."}

        updated_ref_count = 0
        for outbound_item in config_data["outbounds"]:
            if isinstance(outbound_item, dict) and outbound_item.get("type") in ["selector", "urltest"]:
                current_selector_tag = outbound_item.get("tag", "Unnamed Selector")
                
                if current_selector_tag in TAGS_TO_SKIP:
                    logger.debug(f"Skipping modification for selector '{current_selector_tag}' as per user's instruction.")
                    continue

                original_nested_outbounds_list = outbound_item.get("outbounds", [])[:] 
                final_nested_outbounds = [] 
                
                final_nested_outbounds.extend(processed_outbound_tags)
                
                for existing_tag_in_selector in original_nested_outbounds_list:
                    if existing_tag_in_selector not in processed_outbound_tags:
                        final_nested_outbounds.append(existing_tag_in_selector)
                
                if "auto-selector" in current_selector_tag.lower() or "urltest-selector" in current_selector_tag.lower():
                    if "direct" not in final_nested_outbounds:
                        final_nested_outbounds.append("direct")
                
                if "auto-selector" in current_selector_tag.lower() or "urltest-selector" in current_selector_tag.lower():
                    if "proxy" not in final_nested_outbounds:
                        final_nested_outbounds.append("proxy")
                
                seen = set()
                deduplicated_list = []
                for x in final_nested_outbounds:
                    if x not in seen:
                        deduplicated_list.append(x)
                        seen.add(x)
                
                final_nested_outbounds = deduplicated_list

                if final_nested_outbounds != original_nested_outbounds_list:
                    outbound_item["outbounds"] = final_nested_outbounds
                    updated_ref_count += 1
                    logger.debug(f"Updated selector '{current_selector_tag}'. New outbounds: {final_nested_outbounds}")
                else:
                    logger.debug(f"Selector '{current_selector_tag}' not updated (no changes).")
            else:
                logger.debug(f"Skipping non-selector item or malformed selector: {outbound_item.get('tag', 'No Tag')} (Type: {type(outbound_item)})\nContent: {outbound_item}")

        logger.info(f"{updated_ref_count} selektor/urltest outbounds berhasil diperbarui referensinya.")

        new_config_content = json.dumps(config_data, indent=2)
        
        return {
            "status": "success", 
            "message": f"Konfigurasi Sing-Box baru dengan {len(processed_outbound_tags)} outbound berhasil dibuat dan selektor diperbarui.",
            "config_content": new_config_content, 
            "new_outbound_tags": processed_outbound_tags, 
            "processed_outbound_objects": processed_outbound_objects
        }

    except Exception as e:
        logger.error(f"Error during multiple Sing-Box conversion: {e}", exc_info=True)
        return {"status": "error", "message": f"Terjadi error yang nggak terduga saat konversi Sing-Box: {e}"}

if __name__ == '__main__':
    pass
