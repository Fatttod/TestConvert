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
def _clean_and_tag_name(display_name, base_tag):
    """
    Cleans a display name from a VPN link and generates a user-friendly tag.
    Attempts to extract country code and a cleaned provider/server name.
    """
    country_emoji = ""
    cleaned_provider_name = ""
    original_display_name = display_name # Keep original for fallback

    # Strategy 1: Look for (XX) format for country code and then provider name
    # Example: "my.domain.com-(SG)-DigitalOcean-v2" or "(ID) My VPN"
    match = re.search(r'\(\s*([A-Za-z]{2})\s*\)\s*(.*)', display_name)
    if match:
        code = match.group(1).upper()
        if code in COUNTRY_CODE_TO_EMOJI:
            country_emoji = COUNTRY_CODE_TO_EMOJI[code]
            remaining_name = match.group(2).strip()
            # Remove quotes if present
            if remaining_name.startswith('"') and remaining_name.endswith('"'):
                remaining_name = remaining_name[1:-1].strip()
            # Remove common domain-like prefixes
            cleaned_provider_name = re.sub(r'^(.*?\.com|.*?\.net|.*?\.org|.*?\.io|.*?\.xyz|.*?\.me|.*?\.link|.*?\.cloud|.*?\.fun|.*?\.online|.*?\.icu)-*', '', remaining_name, flags=re.IGNORECASE)
            cleaned_provider_name = re.sub(r'[^\w\s\-\(\)\[\]]+', '', cleaned_provider_name) # Remove other special chars
            cleaned_provider_name = cleaned_provider_name.strip().replace(" ", "-").replace("--", "-")
            
    # Strategy 2: If strategy 1 failed for emoji, try to extract country code from start, then clean the rest
    if not country_emoji: 
        country_code_match = re.match(r'^\s*([A-Za-z]{2})\s*(.*)', display_name)
        if country_code_match:
            code = country_code_match.group(1).upper()
            if code in COUNTRY_CODE_TO_EMOJI:
                country_emoji = COUNTRY_CODE_TO_EMOJI[code]
                remaining_name = country_code_match.group(2).strip()
                cleaned_provider_name = re.sub(r'^(.*?\.com|.*?\.net|.*?\.org|.*?\.io|.*?\.xyz|.*?\.me|.*?\.link|.*?\.cloud|.*?\.fun|.*?\.online|.*?\.icu)-*', '', remaining_name, flags=re.IGNORECASE)
                cleaned_provider_name = re.sub(r'[^\w\s\-\(\)\[\]]+', '', cleaned_provider_name)
                cleaned_provider_name = cleaned_provider_name.strip().replace(" ", "-").replace("--", "-")

    # Strategy 3: Clean the whole display name if no specific country code or provider name was found from structured patterns
    if not country_emoji and not cleaned_provider_name:
        cleaned_provider_name = re.sub(r'^(.*?\.com|.*?\.net|.*?\.org|.*?\.io|.*?\.xyz|.*?\.me|.*?\.link|.*?\.cloud|.*?\.fun|.*?\.online|.*?\.icu)-*', '', original_display_name, flags=re.IGNORECASE)
        cleaned_provider_name = re.sub(r'[^\w\s\-\(\)\[\]]+', '', cleaned_provider_name)
        cleaned_provider_name = cleaned_provider_name.strip().replace(" ", "-").replace("--", "-")

    # Form the final tag
    final_tag = base_tag
    if country_emoji and cleaned_provider_name:
        final_tag = f"{base_tag}-{country_emoji}-{cleaned_provider_name}"
    elif country_emoji:
        final_tag = f"{base_tag}-{country_emoji}"
    elif cleaned_provider_name:
        final_tag = f"{base_tag}-{cleaned_provider_name}"
    
    # Final cleanup for any double spaces or dashes
    final_tag = final_tag.replace("  ", " ").strip().replace("--", "-")
    return final_tag.strip('-') # Remove leading/trailing dashes if any


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

        # Tambahkan host dan path untuk websocket/http
        config['host'] = query_params.get('host', [''])[0] 
        config['path'] = query_params.get('path', [''])[0]

        logger.debug(f"Successfully parsed Trojan link: {host}")
        return config
    except Exception as e:
        logger.error(f"Error parsing Trojan link for {trojan_link[:50]}...: {e}")
        return None

# --- FUNGSI INTERNAL UNTUK MEMPROSES SATU LINK (TIDAK DIPANGGIL LANGSUNG DARI APP.PY) ---
def _process_single_singbox_config(vpn_link, existing_tags):
    """
    Parses a single VPN link and returns a Sing-Box outbound object and its generated tag.
    Handles tag deduplication internally.
    """
    new_outbound_object = {}
    new_outbound_tag = ""
    protocol_type = None

    try:
        if "vmess://" in vpn_link:
            parsed_data = parse_vmess_link(vpn_link)
            if parsed_data:
                protocol_type = "vmess"
                base_tag = f"vmess-{parsed_data.get('add', 'NoName')}"
                display_name = parsed_data.get('ps', '')

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
                
                new_outbound_tag = _clean_and_tag_name(display_name, base_tag)

        elif "vless://" in vpn_link:
            parsed_data = parse_vless_link(vpn_link)
            if parsed_data:
                protocol_type = "vless"
                base_tag = f"vless-{parsed_data.get('address', 'NoName')}"
                display_name = parsed_data.get('sni') or parsed_data.get('host') or ""

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
                
                new_outbound_tag = _clean_and_tag_name(display_name, base_tag)

        elif "trojan://" in vpn_link:
            parsed_data = parse_trojan_link(vpn_link)
            if parsed_data:
                protocol_type = "trojan"
                base_tag = f"trojan-{parsed_data.get('address', 'NoName')}"
                
                # Ambil path asli dari parsed_data, yang mungkin mengandung #display_name
                full_path_from_param = parsed_data.get('path', '/')
                actual_websocket_path = "/"
                display_name_from_path = ""

                if '#' in full_path_from_param:
                    path_parts = full_path_from_param.split('#', 1)
                    actual_websocket_path = path_parts[0]
                    display_name_from_path = path_parts[1].strip()
                else:
                    actual_websocket_path = full_path_from_param
                
                new_outbound_object = {
                    "type": "trojan",
                    "tag": base_tag, 
                    "server": parsed_data.get('address', ''),
                    "server_port": parsed_data.get('port', 443),
                    "password": parsed_data.get('password', ''),
                    "flow": parsed_data.get('flow'),
                    "network": parsed_data.get('type', 'tcp'),
                    "tls": True, # Trojan selalu TLS
                    "xudp": True, 
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
                
                new_outbound_tag = _clean_and_tag_name(display_name_from_path, base_tag)
        else:
            return {"status": "error", "message": "Tipe link VPN tidak didukung. Hanya VMess, VLESS, atau Trojan.", "outbound": None, "tag": None}
        
        if not new_outbound_object:
            return {"status": "error", "message": f"Gagal memparse link VPN ({protocol_type}). Cek formatnya.", "outbound": None, "tag": None}

        # Hapus kunci dengan nilai None atau string kosong jika tidak relevan untuk Sing-Box
        keys_to_remove = []
        for key, value in new_outbound_object.items():
            if value is None or (isinstance(value, str) and not value) or (isinstance(value, list) and not value):
                keys_to_remove.append(key)
        for key in keys_to_remove:
            del new_outbound_object[key]

        # Cek duplikasi tag sebelum menambahkan
        original_tag_base = new_outbound_tag
        current_tag = original_tag_base
        suffix = 1
        while current_tag in existing_tags:
            current_tag = f"{original_tag_base}-{suffix}"
            suffix += 1
        
        if current_tag != original_tag_base:
            logger.warning(f"Tag '{original_tag_base}' sudah ada, menggunakan tag baru: '{current_tag}'")
        new_outbound_object["tag"] = current_tag
        new_outbound_tag = current_tag # Update new_outbound_tag to the deduplicated one


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
    # List tag selektor yang TIDAK boleh diotak-atik
    TAGS_TO_SKIP = {
        "WhatsApp",
        "GAMESMAX(ML/FF/AOV)",
        "Route Port Game",
        "Option ADs",
        "Option P0rn"
    }

    try:
        # 1. Muat konfigurasi dasar Sing-Box dari template file SEKALI SAJA
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

        # Kumpulkan semua tag yang sudah ada di template (termasuk yang baru ditambahkan)
        existing_tags_in_final_config = {out.get("tag") for out in config_data["outbounds"] if isinstance(out, dict) and "tag" in out}
        
        processed_outbound_tags = [] # Untuk menyimpan tag dari link yang berhasil diproses

        # 2. Proses setiap link VPN
        for idx, vpn_link in enumerate(vpn_links_list):
            link_result = _process_single_singbox_config(vpn_link, existing_tags_in_final_config)
            
            if link_result["status"] == "success" and link_result["outbound"]:
                new_outbound = link_result["outbound"]
                new_tag = link_result["tag"]
                
                # Tambahkan outbound yang sudah diproses dan deduplicated ke config utama
                config_data["outbounds"].append(new_outbound)
                existing_tags_in_final_config.add(new_tag) # Tambahkan tag ke set untuk deduplikasi selanjutnya
                processed_outbound_tags.append(new_tag)
                logger.info(f"Link {idx+1}: Outbound dengan tag '{new_tag}' berhasil ditambahkan.")
            else:
                logger.warning(f"Link {idx+1}: Gagal memproses link '{vpn_link[:50]}...': {link_result['message']}")
                # return link_result # Jika ingin menghentikan total proses saat ada 1 link gagal

        if not processed_outbound_tags:
            return {"status": "warning", "message": "Tidak ada link VPN yang berhasil diproses. Cek format link lo, Tod."}

        # 3. Perbarui outbounds di selektor dan urltest (sekali setelah semua link diproses)
        updated_ref_count = 0
        for outbound_item in config_data["outbounds"]:
            if isinstance(outbound_item, dict) and outbound_item.get("type") in ["selector", "urltest"]:
                current_selector_tag = outbound_item.get("tag", "Unnamed Selector")
                
                if current_selector_tag in TAGS_TO_SKIP:
                    logger.debug(f"Skipping modification for selector '{current_selector_tag}' as per user's instruction.")
                    continue

                original_nested_outbounds_list = outbound_item.get("outbounds", [])[:] 
                final_nested_outbounds = [] 
                
                # Tambahkan semua tag dari link yang berhasil diproses ke selector
                final_nested_outbounds.extend(processed_outbound_tags)
                
                # Salin outbounds yang sudah ada, kecuali yang sama dengan new_outbound_tag (untuk hindari duplikasi)
                for existing_tag_in_selector in original_nested_outbounds_list:
                    if existing_tag_in_selector not in processed_outbound_tags: # Hindari duplikasi jika tag sudah ditambahkan
                        final_nested_outbounds.append(existing_tag_in_selector)
                
                # Tambahkan 'direct' ke 'auto-selector' dan 'urltest-selector' jika belum ada
                if "auto-selector" in current_selector_tag.lower() or "urltest-selector" in current_selector_tag.lower():
                    if "direct" not in final_nested_outbounds:
                        final_nested_outbounds.append("direct")
                
                # Tambahkan 'proxy' ke 'auto-selector' dan 'urltest-selector' jika belum ada
                if "auto-selector" in current_selector_tag.lower() or "urltest-selector" in current_selector_tag.lower():
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

                if final_nested_outbounds != original_nested_outbounds_list:
                    outbound_item["outbounds"] = final_nested_outbounds
                    updated_ref_count += 1
                    logger.debug(f"Updated selector '{current_selector_tag}'. New outbounds: {final_nested_outbounds}")
                else:
                    logger.debug(f"Selector '{current_selector_tag}' not updated (no changes).")
            else:
                logger.debug(f"Skipping non-selector item or malformed selector: {outbound_item.get('tag', 'No Tag')} (Type: {type(outbound_item)})\nContent: {outbound_item}")

        logger.info(f"{updated_ref_count} selektor/urltest outbounds berhasil diperbarui referensinya.")

        # 4. Dump objek JSON yang sudah di-update menjadi string JSON
        new_config_content = json.dumps(config_data, indent=2)
        
        return {
            "status": "success", 
            "message": f"Konfigurasi Sing-Box baru dengan {len(processed_outbound_tags)} outbound berhasil dibuat dan selektor diperbarui.",
            "config_content": new_config_content, 
            "new_outbound_tags": processed_outbound_tags # Mengembalikan semua tag yang berhasil ditambahkan
        }

    except Exception as e:
        logger.error(f"Error during multiple Sing-Box conversion: {e}", exc_info=True)
        return {"status": "error", "message": f"Terjadi error yang nggak terduga saat konversi Sing-Box: {e}"}

if __name__ == '__main__':
    pass
