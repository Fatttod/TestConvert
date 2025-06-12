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
    Converts a single VMess, VLESS, or Trojan link to a Sing-Box outbound configuration.
    Returns a dictionary of the Sing-Box outbound or None if parsing fails.
    """
    link_str = link_str.strip()
    if link_str.startswith("vmess://"):
        vmess_config = parse_vmess_link(link_str)
        if vmess_config:
            # Sing-Box VMess outbound structure
            return {
                "tag": vmess_config.get("ps", "VMess-" + vmess_config.get("id", "Unknown")),
                "type": "vmess",
                "server": vmess_config.get("add"),
                "server_port": int(vmess_config.get("port")),
                "uuid": vmess_config.get("id"),
                "security": vmess_config.get("scty", "auto"),
                "alter_id": int(vmess_config.get("aid", 0)),
                "network": vmess_config.get("net", "tcp"),
                "tls": {
                    "enabled": vmess_config.get("tls", "") == "tls",
                    "server_name": vmess_config.get("host") if vmess_config.get("host") else vmess_config.get("add"),
                    "insecure": vmess_config.get("skip_cert_verify", False), # Default to false if not specified
                    "disable_sni": False # Add disable_sni based on your requirements
                } if vmess_config.get("tls", "") == "tls" else { "enabled": False },
                "transport": {
                    "type": vmess_config.get("net", "tcp"),
                    "websocket_path": vmess_config.get("path", ""),
                    "websocket_headers": {
                        "Host": vmess_config.get("host", "") if vmess_config.get("host") else vmess_config.get("add", "")
                    },
                    "grpc_service_name": vmess_config.get("path", "") # for gRPC
                } if vmess_config.get("net", "tcp") in ["ws", "grpc"] else None
            }
    elif link_str.startswith("vless://"):
        # VLESS link format: vless://uuid@server:port?params#name
        try:
            parsed_url = urllib.parse.urlparse(link_str)
            user_info, server_port = parsed_url.netloc.split('@')
            server, port = server_port.split(':')
            params = urllib.parse.parse_qs(parsed_url.query)
            tag_name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else server

            # Sing-Box VLESS outbound structure
            return {
                "tag": tag_name,
                "type": "vless",
                "server": server,
                "server_port": int(port),
                "uuid": user_info,
                "flow": params.get("flow", [""])[0] if params.get("flow") else "",
                "tls": {
                    "enabled": params.get("security", [""])[0] == "tls",
                    "server_name": params.get("sni", [""])[0] if params.get("sni") else server,
                    "insecure": params.get("allowInsecure", ["false"])[0].lower() == "true",
                    "disable_sni": False, # Add disable_sni based on your requirements
                    "reality_opts": { # Optional: for Reality
                        "enabled": params.get("security", [""])[0] == "reality",
                        "public_key": params.get("pbk", [""])[0],
                        "short_id": params.get("sid", [""])[0]
                    } if params.get("security", [""])[0] == "reality" else None
                } if params.get("security", [""])[0] in ["tls", "reality"] else { "enabled": False },
                "transport": {
                    "type": params.get("type", ["tcp"])[0],
                    "websocket_path": params.get("path", [""])[0],
                    "websocket_headers": {
                        "Host": params.get("host", [""])[0] if params.get("host") else server
                    },
                    "grpc_service_name": params.get("serviceName", [""])[0] # for gRPC
                } if params.get("type", ["tcp"])[0] in ["ws", "grpc"] else None
            }
        except Exception as e:
            logger.error(f"Error parsing VLESS link for {link_str[:50]}...: {e}")
            return None
    elif link_str.startswith("trojan://"):
        # Trojan link format: trojan://password@server:port?params#name
        try:
            # Parse the URL parts
            parsed_url = urllib.parse.urlparse(link_str)
            password_server_port = parsed_url.netloc
            params = urllib.parse.parse_qs(parsed_url.query)
            tag_name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else parsed_url.netloc

            # Split password from server:port
            password, server_port = password_server_port.split('@', 1)
            server, port = server_port.split(':', 1)

            # Sing-Box Trojan outbound structure
            return {
                "tag": tag_name,
                "type": "trojan",
                "server": server,
                "server_port": int(port),
                "password": password,
                "network": params.get("type", ["tcp"])[0], # Assuming 'type' param can be 'tcp', 'ws', 'grpc'
                "tls": {
                    "enabled": True, # Trojan always uses TLS
                    "server_name": params.get("sni", [""])[0] if params.get("sni") else server,
                    "insecure": params.get("allowInsecure", ["false"])[0].lower() == "true",
                    "disable_sni": False # Add disable_sni based on your requirements
                },
                "transport": {
                    "type": params.get("type", ["tcp"])[0],
                    "websocket_path": params.get("path", [""])[0],
                    "websocket_headers": {
                        "Host": params.get("host", [""])[0] if params.get("host") else server
                    },
                    "grpc_service_name": params.get("serviceName", [""])[0] # for gRPC
                } if params.get("type", ["tcp"])[0] in ["ws", "grpc"] else None
            }
        except Exception as e:
            logger.error(f"Error parsing Trojan link for {link_str[:50]}...: {e}")
            return None
    logger.warning(f"Unsupported link type for {link_str[:50]}...")
    return None

def process_singbox_config(links, template_path="singbox-template.txt"):
    """
    Processes a list of VPN links, converts them to Sing-Box outbounds,
    and integrates them into a base Sing-Box configuration template.
    Ensures generated outbounds are inserted after 'bypass'/'dns-out'
    and 'direct'/'block' are always at the end.
    """
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        logger.info(f"Template Sing-Box berhasil dimuat dari '{template_path}'.")

        # 1. Konversi semua link VPN ke outbounds Sing-Box
        generated_outbounds = []
        for link in links:
            outbound = convert_link_to_singbox_outbound(link)
            if outbound and outbound.get("tag"): # Pastikan outbound valid dan punya tag
                generated_outbounds.append(outbound)
            else:
                logger.warning(f"Gagal mengonversi link atau tag tidak ditemukan: {link[:50]}...")
        
        # Buat map dari outbounds yang baru digenerate agar mudah diakses
        generated_outbounds_map = {ob["tag"]: ob for ob in generated_outbounds}

        # 2. Siapkan daftar outbounds akhir
        final_outbounds_list = []
        inserted_point_found = False
        
        # Pisahkan 'direct' dan 'block' dari outbounds yang ada di template agar bisa ditaruh di akhir
        # Ini penting untuk memastikan 'direct' dan 'block' selalu di paling bawah.
        temp_existing_outbounds = []
        direct_ob_from_template = None
        block_ob_from_template = None

        for ob in config_data.get("outbounds", []):
            if ob.get("tag") == "direct":
                direct_ob_from_template = ob
            elif ob.get("tag") == "block":
                block_ob_from_template = ob
            else:
                temp_existing_outbounds.append(ob)
        
        # 3. Iterasi melalui outbounds yang bukan 'direct'/'block' dari template untuk menyisipkan
        for ob in temp_existing_outbounds:
            final_outbounds_list.append(ob)
            
            # Jika ini adalah 'dns-out' atau 'bypass', sisipkan outbounds yang digenerate di sini
            if not inserted_point_found and (ob.get("tag") == "dns-out" or ob.get("tag") == "bypass"):
                for gen_ob in generated_outbounds:
                    # Hanya tambahkan jika belum ada di final_outbounds_list (untuk menghindari duplikasi jika tag sama)
                    if gen_ob.get("tag") not in [item.get("tag") for item in final_outbounds_list]:
                        final_outbounds_list.append(gen_ob)
                inserted_point_found = True
                logger.debug(f"Outbounds VPN disisipkan setelah '{ob.get('tag')}'.")
        
        # Jika outbounds yang digenerate belum disisipkan (karena 'dns-out'/'bypass' tidak ada di template)
        if not inserted_point_found:
            for gen_ob in generated_outbounds:
                if gen_ob.get("tag") not in [item.get("tag") for item in final_outbounds_list]:
                    final_outbounds_list.append(gen_ob)
            logger.debug("Outbounds VPN disisipkan di akhir list karena titik sisipan spesifik tidak ditemukan.")

        # 4. Pastikan 'direct' dan 'block' ada dan di akhir list
        # Gunakan definisi dari template jika ada, kalau tidak, buat default
        if not any(ob.get("tag") == "direct" for ob in final_outbounds_list):
            if direct_ob_from_template:
                final_outbounds_list.append(direct_ob_from_template)
            else:
                final_outbounds_list.append({"tag": "direct", "protocol": "direct"})
        
        if not any(ob.get("tag") == "block" for ob in final_outbounds_list):
            if block_ob_from_template:
                final_outbounds_list.append(block_ob_from_template)
            else:
                final_outbounds_list.append({"tag": "block", "protocol": "block"})

        config_data["outbounds"] = final_outbounds_list
        logger.info(f"{len(generated_outbounds)} outbounds baru hasil konversi berhasil ditambahkan/disisipkan.")
        
        # --- UPDATE REFERENSI DI SELECTOR/URLTEST OUTBOUNDS ---
        updated_ref_count = 0
        all_final_outbound_tags = [ob["tag"] for ob in config_data["outbounds"]] # Ambil semua tag yang sudah final
        
        for outbound_selector in config_data.get("outbounds", []):
            if outbound_selector.get("type") in ["selector", "urltest"]:
                current_selector_tag = outbound_selector.get("tag", "Unknown Selector")
                original_nested_outbounds_list = outbound_selector.get("outbounds", [])
                
                combined_tags = []
                
                # Tambahkan tag yang baru digenerate oleh proses ini dulu
                for gen_ob in generated_outbounds: # Ambil dari list generated_outbounds asli
                    if gen_ob["tag"] in all_final_outbound_tags and gen_ob["tag"] not in combined_tags:
                        combined_tags.append(gen_ob["tag"])
                
                # Tambahkan tag dari original selector list yang masih ada di final_outbounds_list dan belum ditambahkan
                for tag in original_nested_outbounds_list:
                    if tag in all_final_outbound_tags and tag not in combined_tags:
                        combined_tags.append(tag)
                
                # Tambahkan 'direct' dan 'block' jika belum ada di selector dan ada di final outbounds
                if "direct" in all_final_outbound_tags and "direct" not in combined_tags:
                    combined_tags.append("direct")
                if "block" in all_final_outbound_tags and "block" not in combined_tags:
                    combined_tags.append("block")
                
                if combined_tags != original_nested_outbounds_list:
                    outbound_selector["outbounds"] = combined_tags
                    updated_ref_count += 1
                    logger.debug(f"Updated selector '{current_selector_tag}'. New outbounds: {combined_tags}")
                else:
                    logger.debug(f"Selector '{current_selector_tag}' not updated (no changes).")
            else:
                logger.debug(f"Skipping non-selector item or malformed selector: {outbound_selector.get('tag', 'No Tag')} (Type: {type(outbound_selector)})")

        logger.info(f"{updated_ref_count} selector/urltest outbounds berhasil diperbarui referensinya.")

        new_config_content = json.dumps(config_data, indent=2)
        
        return {
            "status": "success", 
            "message": "Konfigurasi Sing-Box baru sudah dibuat.",
            "config_content": new_config_content, 
        }

    except json.JSONDecodeError as e:
        logger.error(f"Error parsing JSON di template: {e}", exc_info=True)
        return {"status": "error", "message": f"Error parsing JSON di template, Mek! Pastikan formatnya valid dan tidak ada koma yang salah: {e}"}
    except Exception as e:
        logger.error(f"Error during Sing-Box conversion: {e}", exc_info=True)
        return {"status": "error", "message": f"Terjadi error yang nggak terduga saat konversi Sing-Box: {e}"}

