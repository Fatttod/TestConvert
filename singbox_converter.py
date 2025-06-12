import json
import os
import urllib.parse
import base64
import re
import logging
import sys

logger = logging.getLogger(__name__)

# Daftar tag selector yang TIDAK boleh diubah outbounds-nya
EXCLUDED_SELECTOR_TAGS = [
    "WhatsApp",
    "GAMESMAX(ML/FF/AOV)",
    "Route Port Game",
    "Option ADs",
    "Option P0rn"
]

# Mapping kode negara ke simbol bendera Unicode
COUNTRY_EMOJIS = {
    "US": "🇺🇸", "SG": "🇸🇬", "ID": "🇮🇩", "JP": "🇯🇵", "DE": "🇩🇪",
    "FR": "🇫🇷", "UK": "🇬🇧", "CA": "🇨🇦", "AU": "🇦🇺", "NL": "🇳🇱",
    "KR": "🇰🇷", "HK": "🇭🇰", "TW": "🇹🇼", "IN": "🇮🇳", "BR": "🇧🇷",
    "RU": "🇷🇺", "SE": "🇸🇪", "FI": "🇫🇮", "CH": "🇨🇭", "AR": "🇦🇷",
    # Tambahkan lebih banyak jika diperlukan
}

def get_emoji_from_country_code(code):
    # Mengembalikan emoji negara atau globe berwarna jika kode tidak ditemukan
    return COUNTRY_EMOJIS.get(code.upper(), "🌎")

def parse_vmess_link(vmess_link):
    """
    Parses a VMess link (assuming base64 encoded JSON config).
    Returns a dictionary of VMess config, or None if parsing fails.
    """
    try:
        if not vmess_link or not vmess_link.startswith("vmess://"):
            logger.debug(f"VMess link invalid format or empty: {vmess_link[:50]}...")
            return None
        
        encoded_data = vmess_link[len("vmess://"):]
        # Base64 decode with padding correction
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

def convert_link_to_singbox_outbound(link_str, node_counter):
    """
    Converts a VMess, VLESS, or Trojan link string to a Sing-Box outbound configuration.
    Returns a dictionary of Sing-Box outbound config, or None if conversion fails.
    Adds a unique and formatted tag based on country emoji, ISP, and counter.
    """
    outbound = None
    original_tag_name = "Node"
    country_code = ""

    if link_str.startswith("vmess://"):
        vmess_config = parse_vmess_link(link_str)
        if not vmess_config:
            return None
        
        original_tag_name = vmess_config.get("ps", f"VMess_Node_{node_counter}")
        outbound = {
            "tag": original_tag_name, 
            "type": "vmess",
            "server": vmess_config.get("add"),
            "server_port": int(vmess_config.get("port")),
            "uuid": vmess_config.get("id"),
            "security": vmess_config.get("scy", "auto"),
            "alterId": int(vmess_config.get("aid", 0)),
            "network": vmess_config.get("net", "tcp"),
        }
        if vmess_config.get("tls", "") == "tls":
            outbound["tls"] = {
                "enabled": True,
                "server_name": vmess_config.get("host", vmess_config.get("add")),
                "insecure": False,
                "disable_sni": False
            }
            if vmess_config.get("fp"):
                outbound["tls"]["utls"] = {"enabled": True, "fingerprint": vmess_config["fp"]}
            if vmess_config.get("alpn"):
                outbound["tls"]["alpn"] = vmess_config["alpn"].split(',')

        transport_type = vmess_config.get("net", "tcp")
        transport_settings = {}
        if transport_type == "ws":
            transport_settings = {
                "type": "ws",
                "path": vmess_config.get("path", "/"),
                "headers": {"Host": vmess_config.get("host", "")}
            }
        elif transport_type == "grpc":
            transport_settings = {"type": "grpc", "grpc_service_name": vmess_config.get("path", "")}
        if transport_settings:
            outbound["transport"] = transport_settings
    
    elif link_str.startswith("vless://"):
        try:
            parsed_url = urllib.parse.urlparse(link_str)
            user_info, server_info = parsed_url.netloc.split('@')
            uuid = user_info
            server, port = server_info.split(':')
            params = urllib.parse.parse_qs(parsed_url.query)
            
            original_tag_name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"VLESS_Node_{server}"
            outbound = {
                "tag": original_tag_name,
                "type": "vless",
                "server": server,
                "server_port": int(port),
                "uuid": uuid,
                "network": params.get("type", ["tcp"])[0],
            }
            if "security" in params and params["security"][0] == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": params.get("sni", [server])[0],
                    "insecure": False,
                    "disable_sni": False
                }
                if params.get("fp"):
                    outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"][0]}
                if params.get("alpn"):
                    outbound["tls"]["alpn"] = params["alpn"][0].split(',')

            transport_type = params.get("type", ["tcp"])[0]
            transport_settings = {}
            if transport_type == "ws":
                transport_settings = {
                    "type": "ws",
                    "path": params.get("path", ["/"])[0],
                    "headers": {"Host": params.get("host", [""])[0]}
                }
            elif transport_type == "grpc":
                transport_settings = {"type": "grpc", "grpc_service_name": params.get("serviceName", [""])[0]}
            if transport_settings:
                outbound["transport"] = transport_settings
        except Exception as e:
            logger.error(f"Error parsing VLESS link for {link_str[:50]}...: {e}")
            return None
    
    elif link_str.startswith("trojan://"):
        try:
            parsed_url = urllib.parse.urlparse(link_str)
            password = parsed_url.username
            server, port = parsed_url.netloc.split('@')[1].split(':') if '@' in parsed_url.netloc else parsed_url.netloc.split(':')
            params = urllib.parse.parse_qs(parsed_url.query)
            
            original_tag_name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"Trojan_Node_{server}"
            outbound = {
                "tag": original_tag_name,
                "type": "trojan",
                "server": server,
                "server_port": int(port),
                "password": password,
            }
            if "security" in params and params["security"][0] == "tls" or "sni" in params:
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": params.get("sni", [server])[0],
                    "insecure": False,
                    "disable_sni": False
                }
                if params.get("fp"):
                    outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"][0]}
                if params.get("alpn"):
                    outbound["tls"]["alpn"] = params["alpn"][0].split(',')

            transport_type = params.get("type", ["tcp"])[0]
            transport_settings = {}
            if transport_type == "ws":
                transport_settings = {
                    "type": "ws",
                    "path": params.get("path", ["/"])[0],
                    "headers": {"Host": params.get("host", [""])[0]}
                }
            elif transport_type == "grpc":
                transport_settings = {"type": "grpc", "grpc_service_name": params.get("serviceName", [""])[0]}
            if transport_settings:
                outbound["transport"] = transport_settings
        except Exception as e:
            logger.error(f"Error parsing Trojan link for {link_str[:50]}...: {e}")
            return None

    else:
        logger.warning(f"Unsupported link type for conversion: {link_str[:50]}...")
        return None

    if outbound:
        # Logika pembentukan tag baru: simbol bendera + nama ISP/nama asli + nomor urut
        display_name = original_tag_name
        country_code = ""
        
        # Coba ekstrak kode negara (misal US, SG, ID) dari awal nama
        match_country = re.match(r'^([A-Za-z]{2})\s*-\s*(.*)', display_name)
        if match_country:
            country_code = match_country.group(1).upper()
            remaining_name = match_country.group(2).strip()
            display_name = remaining_name
        
        # Hapus bagian dalam kurung siku jika ada (misal [VLESS-TLS])
        display_name = re.sub(r'\s*\[.*?\]\s*', '', display_name).strip()

        # Cek apakah nama display_name sudah cukup informatif, kalau tidak, pakai original_tag_name utuh
        # Atau jika setelah dibersihkan jadi kosong, pakai nama aslinya
        if not display_name or display_name.lower().startswith(("vmess", "vless", "trojan", "node")):
            display_name = original_tag_name.replace('_', ' ').strip() # Ganti underscore jadi spasi

        emoji = get_emoji_from_country_code(country_code)
        
        final_tag = f"{emoji} {display_name} #{node_counter}".strip()
        outbound["tag"] = final_tag
        logger.debug(f"Converted link to Sing-Box outbound with formatted tag: {outbound.get('tag')}")
        return outbound
    return None


def process_singbox_config(vmess_links_str, template_content, output_options=None):
    """
    Processes VMess/VLESS/Trojan links and integrates them into a Sing-Box configuration template.
    It puts converted outbounds based on the user's specified order.
    Excludes certain selector tags from being updated.
    """
    try:
        logger.debug(f"Received template_content (first 200 chars): {template_content[:200]}")
        
        config_data = json.loads(template_content)
        logger.debug(f"Successfully parsed config_data keys: {config_data.keys()}")

        vmess_links = [link.strip() for link in vmess_links_str.split('\n') if link.strip()]

        converted_outbounds = []
        node_counter = 1
        for link in vmess_links:
            outbound = convert_link_to_singbox_outbound(link, node_counter)
            if outbound:
                converted_outbounds.append(outbound)
                node_counter += 1
            else:
                logger.warning(f"Failed to convert link: {link}")

        if not converted_outbounds:
            logger.warning("Nggak ada link VPN valid yang dikonversi. Melanjutkan dengan outbounds template dan default.")

        # Default fixed outbounds
        direct_outbound = {"type": "direct", "tag": "direct"}
        bypass_outbound = {"type": "direct", "tag": "bypass"}
        block_outbound = {"type": "block", "tag": "block"}
        dns_out_outbound = {"type": "dns", "tag": "dns-out"}

        existing_default_tags = ["direct", "bypass", "block", "dns-out"]
        
        template_outbound_map = {o["tag"]: o for o in config_data["outbounds"] if "tag" in o}

        final_outbounds = []

        desired_initial_selector_tags = [
            "Internet",
            "Best Latency",
            "Lock Region ID",
            "WhatsApp",
            "GAMESMAX(ML/FF/AOV)",
            "Route Port Game",
            "Option ADs",
            "Option P0rn"
        ]

        # Tambahkan selector/urltest awal sesuai urutan
        for tag_name in desired_initial_selector_tags:
            if tag_name in template_outbound_map:
                final_outbounds.append(template_outbound_map[tag_name])
            else:
                # Jika selector tidak ada di template, tambahkan placeholder default
                if tag_name == "Internet":
                    final_outbounds.append({
                        "tag": "Internet",
                        "type": "selector",
                        "outbounds": ["Best Latency", "direct"] # Default awal
                    })
                elif tag_name == "Best Latency":
                     final_outbounds.append({
                        "type": "urltest",
                        "tag": "Best Latency",
                        "outbounds": [], # Akan diisi dengan akun konversi + direct
                        "url": "https://www.gstatic.com/generate_204",
                        "interval": "30s"
                    })
                elif tag_name == "Lock Region ID":
                     final_outbounds.append({
                        "type": "selector",
                        "tag": "Lock Region ID",
                        "outbounds": []
                    })
                elif tag_name in EXCLUDED_SELECTOR_TAGS:
                    # Untuk tag yang dikecualikan, jika tidak di template, tambahkan dengan outbounds default
                    final_outbounds.append({
                        "type": "selector",
                        "tag": tag_name,
                        "outbounds": ["direct", "Internet", "Best Latency", "Lock Region ID"] # Default umum
                    })
                logger.warning(f"Selector '{tag_name}' tidak ditemukan di template. Menambahkan placeholder default.")

        # Tambahkan akun hasil konversi
        final_outbounds.extend(converted_outbounds)

        # Tambahkan outbounds lain dari template yang tidak termasuk dalam kategori di atas
        # dan belum ditambahkan ke final_outbounds.
        current_final_outbound_tags = {o["tag"] for o in final_outbounds if "tag" in o}
        
        for outbound in config_data["outbounds"]:
            tag = outbound.get("tag")
            if tag not in current_final_outbound_tags and tag not in existing_default_tags:
                final_outbounds.append(outbound)
                current_final_outbound_tags.add(tag) 

        # Tambahkan outbounds default di bagian paling akhir, pastikan tidak duplikat
        if direct_outbound["tag"] not in current_final_outbound_tags: final_outbounds.append(direct_outbound)
        if bypass_outbound["tag"] not in current_final_outbound_tags: final_outbounds.append(bypass_outbound)
        if block_outbound["tag"] not in current_final_outbound_tags: final_outbounds.append(block_outbound)
        if dns_out_outbound["tag"] not in current_final_outbound_tags: final_outbounds.append(dns_out_outbound)
        
        config_data["outbounds"] = final_outbounds

        # --- UPDATE REFERENSI UNTUK SELECTOR/URLTEST (DENGAN PENGECUALIAN) ---
        all_outbound_tags = [o["tag"] for o in final_outbounds if "tag" in o]
        logger.debug(f"All available outbound tags after reordering: {all_outbound_tags}")

        updated_ref_count = 0
        for outbound_item in config_data["outbounds"]:
            current_selector_tag = outbound_item.get("tag")
            
            # Lewati jika ada di daftar pengecualian
            if current_selector_tag in EXCLUDED_SELECTOR_TAGS:
                logger.info(f"Melewati selector '{current_selector_tag}' karena ada di daftar pengecualian.")
                continue 

            if (outbound_item.get("type") == "selector" or \
                outbound_item.get("type") == "urltest") and \
                "outbounds" in outbound_item and \
                isinstance(outbound_item["outbounds"], list):
                
                original_nested_outbounds_list = list(outbound_item["outbounds"])
                
                new_nested_outbounds = []

                # Untuk "Internet", "Best Latency", "Lock Region ID", tambahkan semua akun VPN hasil konversi
                if current_selector_tag in ["Internet", "Best Latency", "Lock Region ID"]:
                    # Tambahkan akun konversi terlebih dahulu
                    for converted_o in converted_outbounds:
                        if converted_o["tag"] not in new_nested_outbounds:
                            new_nested_outbounds.append(converted_o["tag"])
                    
                    # Lalu tambahkan "direct"
                    if "direct" not in new_nested_outbounds and "direct" in all_outbound_tags:
                        new_nested_outbounds.append("direct")

                    # Untuk "Internet", pastikan "Best Latency" dan "Lock Region ID" ada di awal
                    if current_selector_tag == "Internet":
                        if "Best Latency" in all_outbound_tags and "Best Latency" not in new_nested_outbounds:
                            new_nested_outbounds.insert(0, "Best Latency") # Prioritaskan Best Latency
                        
                        # Cek posisi "Lock Region ID" agar tidak di depan Best Latency
                        if "Lock Region ID" in all_outbound_tags and "Lock Region ID" not in new_nested_outbounds:
                            insert_index = 0
                            if "Best Latency" in new_nested_outbounds:
                                insert_index = new_nested_outbounds.index("Best Latency") + 1
                            new_nested_outbounds.insert(insert_index, "Lock Region ID")
                    
                else: # Untuk selector lain yang tidak dikecualikan dan bukan di atas
                    # Pertahankan outbounds asli yang masih valid
                    for original_tag_in_selector in original_nested_outbounds_list:
                        if original_tag_in_selector in all_outbound_tags and original_tag_in_selector not in new_nested_outbounds:
                            new_nested_outbounds.append(original_tag_in_selector)
                    
                    # Tambahkan akun konversi jika belum ada
                    for converted_o in converted_outbounds:
                        if converted_o["tag"] not in new_nested_outbounds:
                            new_nested_outbounds.append(converted_o["tag"])

                    # Tambahkan default tags jika belum ada di selector ini
                    for default_tag_check in ["direct", "bypass", "block", "dns-out"]:
                        if default_tag_check not in new_nested_outbounds and default_tag_check in all_outbound_tags:
                            new_nested_outbounds.append(default_tag_check)

                # Hanya update jika ada perubahan
                if new_nested_outbounds != original_nested_outbounds_list:
                    outbound_item["outbounds"] = new_nested_outbounds
                    updated_ref_count += 1
                    logger.debug(f"Updated selector '{current_selector_tag}'. New outbounds: {new_nested_outbounds}")
                else:
                    logger.debug(f"Selector '{current_selector_tag}' not updated (no changes).")
            else:
                logger.debug(f"Skipping non-selector item or malformed selector: {outbound_item.get('tag', 'No Tag')} (Type: {type(outbound_item.get('type'))})")


        logger.info(f"{updated_ref_count} selector/urltest outbounds berhasil diperbarui referensinya.")

        new_config_content = json.dumps(config_data, indent=2)
        
        return {
            "status": "success", 
            "message": "Konfigurasi Sing-Box baru sudah dibuat.",
            "config_content": new_config_content, 
        }

    except Exception as e:
        logger.error(f"Error during Sing-Box conversion: {e}", exc_info=True)
        return {"status": "error", "message": f"Terjadi error yang nggak terduga saat konversi Sing-Box: {e}"}

if __name__ == '__main__':
    print("Mek, file ini adalah modul logika Sing-Box. Jalankan 'app.py' untuk UI-nya ya.")
            
