# singbox_converter.py
import json
import os
import urllib.parse
import base64
import re
import logging
import sys

logger = logging.getLogger(__name__)

# --- FUNGSI DARI main.txt LO, DENGAN SEDIKIT PENYESUAIAN LOGGING & ERROR HANDLING ---

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

def convert_link_to_singbox_outbound(link_str):
    """
    Mengkonversi link VPN (Trojan, VLESS, VMess) ke format JSON Sing-Box outbound.
    Output: outbound_config dengan tag awal (tanpa angka depan)
    """
    if not link_str or not isinstance(link_str, str):
        logger.warning(f"Invalid input link_str: {link_str}")
        return None

    try:
        parsed_url = urllib.parse.urlparse(link_str)
        scheme = parsed_url.scheme.lower()
        
        outbound_config = {
            "domain_strategy": "ipv4_only",
            "multiplex": {"protocol": "smux", "max_streams": 32}
        }
        
        query_params = urllib.parse.parse_qs(parsed_url.query)
        security = query_params.get('security', [''])[0]
        link_type = query_params.get('type', [''])[0]
        host = query_params.get('host', [''])[0] 
        path = urllib.parse.unquote(query_params.get('path', [''])[0]) if query_params.get('path') else ""
        sni = query_params.get('sni', [''])[0]
        fingerprint = query_params.get('fp', [''])[0]
        flow = query_params.get('flow', [''])[0]

        tag_raw = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{parsed_url.hostname or 'unknown'}:{parsed_url.port or 'unknown'}"
        tag_cleaned = re.sub(r"^\[\d+\]\s*", "", tag_raw).strip()
        
        outbound_config["tag"] = tag_cleaned if tag_cleaned else "unknown_vpn_tag"
        outbound_config["server"] = parsed_url.hostname
        outbound_config["server_port"] = parsed_url.port if parsed_url.port else 443

        outbound_config["tls"] = {
            "enabled": security == "tls",
            "server_name": sni if sni else host if host else (parsed_url.hostname if parsed_url.hostname else "localhost"), # Fallback for server_name
            "insecure": True 
        }
        if fingerprint:
            outbound_config["tls"]["utls"] = {"enabled": True, "fingerprint": fingerprint}
        
        if link_type == "ws":
            outbound_config["transport"] = {
                "type": "ws",
                "path": path,
                "headers": {"Host": host if host else (parsed_url.hostname if parsed_url.hostname else "localhost")},
                "early_data_header_name": "Sec-WebSocket-Protocol"
            }
        elif link_type == "grpc":
            outbound_config["transport"] = {
                "type": "grpc",
                "service_name": path.strip('/') if path else ""
            }

        if scheme == "trojan":
            outbound_config["type"] = "trojan"
            outbound_config["password"] = parsed_url.username
        
        elif scheme == "vless":
            outbound_config["type"] = "vless"
            outbound_config["uuid"] = parsed_url.username
            outbound_config["network"] = "tcp" # Default
            if link_type == "ws": outbound_config["network"] = "ws"
            elif link_type == "grpc": outbound_config["network"] = "grpc"

            if flow:
                outbound_config["flow"] = flow

        elif scheme == "vmess":
            vmess_data = parse_vmess_link(link_str)
            if vmess_data:
                outbound_config["type"] = "vmess"
                outbound_config["uuid"] = vmess_data.get("id")
                outbound_config["alter_id"] = vmess_data.get("aid", 0)
                outbound_config["security"] = vmess_data.get("scy", "auto")
                outbound_config["server"] = vmess_data.get("add", parsed_url.hostname)
                outbound_config["server_port"] = vmess_data.get("port", parsed_url.port)
                outbound_config["network"] = vmess_data.get("net", "tcp")

                if vmess_data.get("tls") == "tls":
                    outbound_config["tls"]["enabled"] = True
                    outbound_config["tls"]["server_name"] = vmess_data.get("host", outbound_config["tls"]["server_name"])
                    if vmess_data.get("fp"):
                        outbound_config["tls"]["utls"] = {"enabled": True, "fingerprint": vmess_data["fp"]}

                if vmess_data.get("net") == "ws":
                    outbound_config["transport"] = {
                        "type": "ws",
                        "path": vmess_data.get("path", ""),
                        "headers": {"Host": vmess_data.get("host", outbound_config["server"])}
                    }
                elif vmess_data.get("net") == "grpc":
                    outbound_config["transport"] = {
                        "type": "grpc",
                        "service_name": vmess_data.get("path", "").strip('/')
                    }
                if vmess_data.get("v") == "1" and vmess_data.get("net") == "tcp":
                    outbound_config.pop("multiplex", None)
            else:
                logger.warning(f"Skipping VMess link due to parsing error (vmess_data is None): {link_str[:50]}...")
                return None
        else:
            logger.warning(f"Protocol type not recognized or supported: {scheme} for link: {link_str[:50]}...")
            return None
            
        return outbound_config
    except Exception as e:
        logger.error(f"Error converting link {link_str[:50]}...: {e}", exc_info=True)
        return None

def split_links_if_needed(input_links_raw):
    """
    Checks and separates strings containing multiple concatenated VPN links.
    Returns a list containing each separated link.
    """
    protocols = ["vless://", "trojan://", "vmess://", "ss://", "ssr://", "socks://", "http://"]
    separated_links = []
    
    for line in input_links_raw:
        if not isinstance(line, str): # Pastikan input adalah string
            logger.warning(f"Skipping non-string input in split_links_if_needed: {type(line)}")
            continue

        found_splits = False
        pattern = '|'.join(map(re.escape, protocols))
        
        matches = list(re.finditer(pattern, line))
        
        if len(matches) > 1: # More than one protocol prefix found in a single line
            found_splits = True
            for i in range(len(matches)):
                start_index = matches[i].start()
                if i < len(matches) - 1:
                    end_index = matches[i+1].start()
                    separated_links.append(line[start_index:end_index].strip())
                else: # Last link in the line
                    separated_links.append(line[start_index:].strip())
        
        if not found_splits and line.strip(): # If only 1 or no protocols found concatenated, add as is
            separated_links.append(line.strip())
            
    logger.debug(f"Split links result: {separated_links}")
    return separated_links

# --- FUNGSI UTAMA UNTUK MEMPROSES CONFIG SING-BOX (diadaptasi dari main.txt) ---

def process_singbox_config(input_links_raw_message: str, template_content_string: str) -> dict:
    """
    Fungsi inti untuk memproses konversi dan mengupdate konfigurasi Sing-Box.
    Fungsi ini menerima langsung konten template sebagai string dari app.py.
    """
    try:
        if not template_content_string.strip():
            return {"status": "error", "message": "❌ Error: Konten template Sing-Box kosong. Pastikan file template tidak kosong!"}
            
        # Hapus komentar // dari JSON sebelum parsing (regex lebih robust)
        # Regex ini hanya menghapus baris yang seluruhnya komentar
        cleaned_content_for_json = re.sub(r'^\s*//.*$', '', template_content_string, flags=re.MULTILINE).strip()
        
        if not cleaned_content_for_json:
            return {"status": "error", "message": f"❌ Error: Konten template yang dibersihkan kosong atau hanya berisi komentar. Pastikan ada konfigurasi JSON yang valid!"}

        try:
            config_data = json.loads(cleaned_content_for_json)
            logger.info("Template config berhasil dibaca dan diparsing.")
            logger.debug(f"Parsed config_data keys: {config_data.keys()}")
        except json.JSONDecodeError as e:
            return {"status": "error", "message": f"❌ Error parsing JSON di template, Mek! Pastikan formatnya valid dan tidak ada koma yang salah: {e}"}

        # Inisialisasi outbounds jika tidak ada atau bukan list
        if "outbounds" not in config_data or not isinstance(config_data["outbounds"], list):
            logger.warning("Kunci 'outbounds' tidak ditemukan atau bukan list di file JSON template. Membuat list outbounds baru.")
            config_data["outbounds"] = []

        input_links_processed = split_links_if_needed([input_links_raw_message])
        logger.debug(f"Input links after splitting: {input_links_processed}")

        new_vpn_outbounds_objects = []
        new_vpn_tags = [] # Untuk menyimpan tags VPN baru
        
        logger.info("Memproses link baru...")
        counter = 1
        for link in input_links_processed:
            cleaned_link = link.strip()
            if cleaned_link:
                converted_outbound = convert_link_to_singbox_outbound(cleaned_link)
                if converted_outbound and isinstance(converted_outbound, dict):
                    original_tag = converted_outbound.get("tag", f"vpn_new_{counter}")
                    # Tambahkan nomor urut ke tag agar unik (misal: "My VPN - 1")
                    final_new_tag = f"{original_tag} - {counter}"
                    converted_outbound["tag"] = final_new_tag
                    new_vpn_outbounds_objects.append(converted_outbound)
                    new_vpn_tags.append(final_new_tag) # Simpan tag baru
                    counter += 1
                else:
                    logger.warning(f"Konversi link '{cleaned_link[:50]}...' menghasilkan nilai tidak valid (bukan dictionary atau None).")
            else:
                logger.debug(f"Skipping empty cleaned_link in input_links_processed.")
        
        if not new_vpn_outbounds_objects:
            return {"status": "warning", "message": "❌ Nggak ada link VPN baru yang berhasil dikonversi, Tod. Coba cek lagi format link-nya atau gua nggak support protokol itu."}

        # --- Filter outbounds yang sudah ada (hapus hanya VPN lama berdasarkan tipe) ---
        vpn_types_to_remove = ["trojan", "vless", "vmess", "shadowsocks", "ssr", "socks", "http"]
        
        filtered_outbounds = []
        removed_old_vpn_count = 0
        old_vpn_tags_to_remove = set()
 
        for outbound_item in config_data["outbounds"]:
            if isinstance(outbound_item, dict) and outbound_item.get("type") in vpn_types_to_remove:
                removed_old_vpn_count += 1
                if isinstance(outbound_item.get("tag"), str):
                    old_vpn_tags_to_remove.add(outbound_item["tag"])
            else:
                filtered_outbounds.append(outbound_item)
        
        logger.info(f"{removed_old_vpn_count} akun VPN lama (tipe tertentu) dihapus dari konfigurasi.")
        logger.debug(f"Old VPN tags removed: {old_vpn_tags_to_remove}")

        # --- Cari posisi untuk menyisipkan akun VPN baru ---
        insert_index = -1
        for i in range(len(filtered_outbounds) - 1, -1, -1):
            outbound_item = filtered_outbounds[i]
            if isinstance(outbound_item, dict) and \
               outbound_item.get("tag") == "Option P0rn" and \
               outbound_item.get("type") == "selector":
                insert_index = i + 1
                break
        
        if insert_index != -1:
            filtered_outbounds[insert_index:insert_index] = new_vpn_outbounds_objects
            logger.info(f"{len(new_vpn_outbounds_objects)} akun VPN baru berhasil ditambahkan di posisi yang ditentukan.")
        else:
            logger.warning("Posisi 'Option P0rn' tidak ditemukan dalam template. Akun VPN baru ditambahkan di akhir outbounds yang difilter.")
            filtered_outbounds.extend(new_vpn_outbounds_objects)

        config_data["outbounds"] = filtered_outbounds
        logger.debug(f"Current outbounds after adding new VPNs: {json.dumps(config_data['outbounds'], indent=2)}")

        # --- Update referensi di outbounds selector/urltest (hanya untuk yang spesifik) ---
        logger.info("Memperbarui referensi di Selector/URLTest (Internet, Best Latency, Lock Region ID, proxy, Porn, Telegram)...")
        updated_ref_count = 0

        target_selectors = {"Internet", "Best Latency", "Lock Region ID", "proxy", "Porn", "Telegram"} # Ditambah dari original main.txt

        for outbound_selector in config_data["outbounds"]:
            logger.debug(f"Processing selector: Type: {type(outbound_selector)}, Content: {outbound_selector}") 

            if isinstance(outbound_selector, dict) and \
               isinstance(outbound_selector.get("tag"), str) and \
               outbound_selector["tag"] in target_selectors and \
               "outbounds" in outbound_selector and \
               isinstance(outbound_selector["outbounds"], list):
                
                current_selector_tag = outbound_selector["tag"]
                original_nested_outbounds_list = outbound_selector["outbounds"]
                final_nested_outbounds = []
                seen_tags = set()
             
                for tag_name in original_nested_outbounds_list:
                    if isinstance(tag_name, str) and tag_name not in old_vpn_tags_to_remove and tag_name not in seen_tags:
                        final_nested_outbounds.append(tag_name)
                        seen_tags.add(tag_name)
                    else:
                        logger.debug(f"Skipping non-string or already seen tag_name in selector {current_selector_tag}: {tag_name}")
                
                # --- START: BLOK LOGIKA UNTUK SELECTOR ---
                if current_selector_tag == "Internet" or current_selector_tag == "Best Latency" or current_selector_tag == "proxy" or current_selector_tag == "Porn" or current_selector_tag == "Telegram":
                    insert_vpn_idx = 0
                    if "Best Latency" in final_nested_outbounds:
                        insert_vpn_idx = final_nested_outbounds.index("Best Latency") + 1
                    elif "direct" in final_nested_outbounds: # Tambahan: sisipkan sebelum direct
                         insert_vpn_idx = final_nested_outbounds.index("direct") 
                    
                    for tag in new_vpn_tags:
                        if tag not in seen_tags:
                            final_nested_outbounds.insert(insert_vpn_idx, tag)
                            seen_tags.add(tag)
                            insert_vpn_idx += 1
                
                    # Pastikan "direct" ada jika memang seharusnya ada dan belum ditambahkan
                    if "direct" in original_nested_outbounds_list and "direct" not in seen_tags:
                        final_nested_outbounds.append("direct")
                        seen_tags.add("direct")

                    # Perbaiki bagian ini agar tidak ada duplikasi common_tag
                    # Logika ini bertujuan untuk memastikan common_tag yang *bukan* selector saat ini dan *belum* ada, ditambahkan.
                    # Asumsi: common_tag ini biasanya ada di akhir list
                    for common_tag in ["Internet", "Lock Region ID", "direct", "proxy", "Porn", "Telegram"]: # Tambahan common_tag
                        if common_tag in original_nested_outbounds_list and common_tag not in seen_tags: # Hapus check common_tag != current_selector_tag
                            final_nested_outbounds.append(common_tag)
                            seen_tags.add(common_tag)

                elif current_selector_tag == "Lock Region ID": # Ini baris yang lo tunjuk, Mek, SEKARANG BENAR INDENTASINYA
                    temp_locked_region_outbounds = []
                    for tag in new_vpn_tags:
                        if isinstance(tag, str):
                            temp_locked_region_outbounds.append(tag)
                        else:
                            logger.warning(f"Skipping non-string new_vpn_tag for Lock Region ID: {tag}")
                    final_nested_outbounds = temp_locked_region_outbounds # Ganti seluruh isinya
                # --- END: BLOK LOGIKA UNTUK SELECTOR ---
                
                # Hanya update jika ada perubahan pada list outbounds nested
                if final_nested_outbounds != original_nested_outbounds_list:
                    outbound_selector["outbounds"] = final_nested_outbounds
                    updated_ref_count += 1
                    logger.debug(f"Updated selector '{current_selector_tag}'. New outbounds: {final_nested_outbounds}")
                else:
                    logger.debug(f"Selector '{current_selector_tag}' not updated (no changes).")
            else:
                logger.debug(f"Skipping non-selector item or malformed selector: {outbound_selector.get('tag', 'No Tag')} (Type: {type(outbound_selector)})")

        logger.info(f"{updated_ref_count} selector/urltest outbounds berhasil diperbarui referensinya.")

        # Dump objek JSON yang sudah di-update menjadi string JSON
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
    print("Mek, file ini adalah modul logika Sing-Box. Jalankan 'app.py' untuk UI-nya ya!")
    sys.exit(0)

