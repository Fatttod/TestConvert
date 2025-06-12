# singbox_converter.py (Revisi Final)
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
    Converts a VMess, VLESS, or Trojan link string to a Sing-Box outbound configuration.
    Currently supports: VMess (base64 JSON), VLESS (raw URL), Trojan (raw URL).
    Returns a dictionary of Sing-Box outbound config, or None if conversion fails.
    """
    if link_str.startswith("vmess://"):
        vmess_config = parse_vmess_link(link_str)
        if not vmess_config:
            return None
        
        # Mapping VMess config ke Sing-Box outbound
        outbound = {
            "tag": vmess_config.get("ps", "VMess_Node"), # 'ps' is the node name in VMess
            "type": "vmess",
            "server": vmess_config.get("add"),
            "server_port": int(vmess_config.get("port")),
            "uuid": vmess_config.get("id"),
            "security": vmess_config.get("scy", "auto"), # 'scy' is security/encryption method
            "alterId": int(vmess_config.get("aid", 0)),
            "network": vmess_config.get("net", "tcp"),
        }

        # Tambahkan TLS jika 'tls' ada dan true
        if vmess_config.get("tls", "") == "tls":
            outbound["tls"] = {
                "enabled": True,
                "server_name": vmess_config.get("host", vmess_config.get("add")),
                "insecure": False,
                "disable_sni": False
            }
            if vmess_config.get("fp"): # fingerprint
                outbound["tls"]["utls"] = {"enabled": True, "fingerprint": vmess_config["fp"]}
            if vmess_config.get("alpn"):
                outbound["tls"]["alpn"] = vmess_config["alpn"].split(',')


        # Transport settings (ws, http, grpc, quic, etc.)
        transport_type = vmess_config.get("net", "tcp")
        transport_settings = {}

        if transport_type == "ws":
            transport_settings = {
                "type": "ws",
                "websocket_path": vmess_config.get("path", "/"),
                "websocket_headers": {
                    "Host": vmess_config.get("host", "")
                }
            }
        elif transport_type == "grpc":
            transport_settings = {
                "type": "grpc",
                "grpc_service_name": vmess_config.get("path", "")
            }
        # Tambahkan konfigurasi transport lainnya jika diperlukan (e.g., http, quic)

        if transport_settings:
            outbound["transport"] = transport_settings
        
        logger.debug(f"Converted VMess link to Sing-Box outbound: {outbound.get('tag')}")
        return outbound
    
    elif link_str.startswith("vless://"):
        try:
            # Parse VLESS link
            parsed_url = urllib.parse.urlparse(link_str)
            user_info, server_info = parsed_url.netloc.split('@')
            uuid = user_info
            server, port = server_info.split(':')
            params = urllib.parse.parse_qs(parsed_url.query)
            
            tag = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"VLESS_Node_{server}"

            outbound = {
                "tag": tag,
                "type": "vless",
                "server": server,
                "server_port": int(port),
                "uuid": uuid,
                "network": params.get("type", ["tcp"])[0],
            }

            # TLS settings
            if "security" in params and params["security"][0] == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": params.get("sni", [server])[0],
                    "insecure": False,
                    "disable_sni": False
                }
                if params.get("fp"): # fingerprint
                    outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"][0]}
                if params.get("alpn"):
                    outbound["tls"]["alpn"] = params["alpn"][0].split(',')

            # Transport settings
            transport_type = params.get("type", ["tcp"])[0]
            transport_settings = {}
            if transport_type == "ws":
                transport_settings = {
                    "type": "ws",
                    "websocket_path": params.get("path", ["/"])[0],
                    "websocket_headers": {
                        "Host": params.get("host", [""])[0]
                    }
                }
            elif transport_type == "grpc":
                transport_settings = {
                    "type": "grpc",
                    "grpc_service_name": params.get("serviceName", [""])[0]
                }
            # Tambahkan konfigurasi transport lainnya jika diperlukan

            if transport_settings:
                outbound["transport"] = transport_settings

            logger.debug(f"Converted VLESS link to Sing-Box outbound: {outbound.get('tag')}")
            return outbound
        except Exception as e:
            logger.error(f"Error parsing VLESS link for {link_str[:50]}...: {e}")
            return None
    
    elif link_str.startswith("trojan://"):
        try:
            # Parse Trojan link
            # Format: trojan://password@server:port?param=value#tag
            parsed_url = urllib.parse.urlparse(link_str)
            password = parsed_url.username
            server, port = parsed_url.netloc.split('@')[1].split(':') if '@' in parsed_url.netloc else parsed_url.netloc.split(':')
            params = urllib.parse.parse_qs(parsed_url.query)
            
            tag = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"Trojan_Node_{server}"

            outbound = {
                "tag": tag,
                "type": "trojan",
                "server": server,
                "server_port": int(port),
                "password": password,
            }

            # TLS settings (Trojan usually implies TLS)
            if "security" in params and params["security"][0] == "tls" or "sni" in params:
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": params.get("sni", [server])[0],
                    "insecure": False,
                    "disable_sni": False
                }
                if params.get("fp"): # fingerprint
                    outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"][0]}
                if params.get("alpn"):
                    outbound["tls"]["alpn"] = params["alpn"][0].split(',')


            # Transport settings
            transport_type = params.get("type", ["tcp"])[0]
            transport_settings = {}
            if transport_type == "ws":
                transport_settings = {
                    "type": "ws",
                    "websocket_path": params.get("path", ["/"])[0],
                    "websocket_headers": {
                        "Host": params.get("host", [""])[0]
                    }
                }
            elif transport_type == "grpc":
                transport_settings = {
                    "type": "grpc",
                    "grpc_service_name": params.get("serviceName", [""])[0]
                }
            # Tambahkan konfigurasi transport lainnya jika diperlukan

            if transport_settings:
                outbound["transport"] = transport_settings
            
            logger.debug(f"Converted Trojan link to Sing-Box outbound: {outbound.get('tag')}")
            return outbound
        except Exception as e:
            logger.error(f"Error parsing Trojan link for {link_str[:50]}...: {e}")
            return None

    else:
        logger.warning(f"Unsupported link type for conversion: {link_str[:50]}...")
        return None

def process_singbox_config(vmess_links_str, template_content, output_options=None):
    """
    Processes VMess/VLESS/Trojan links and integrates them into a Sing-Box configuration template.
    It puts converted outbounds first, then 'bypass' and 'dns-out'.
    Excludes certain selector tags from being updated.
    """
    try:
        # Debugging: Cek template_content yang masuk
        logger.debug(f"Received template_content (first 200 chars): {template_content[:200]}")
        
        # Parse template JSON
        config_data = json.loads(template_content)
        logger.debug(f"Successfully parsed config_data keys: {config_data.keys()}")

        # Pisahkan link VMess/VLESS/Trojan berdasarkan baris baru
        vmess_links = [link.strip() for link in vmess_links_str.split('\n') if link.strip()]

        converted_outbounds = []
        for link in vmess_links:
            outbound = convert_link_to_singbox_outbound(link)
            if outbound:
                converted_outbounds.append(outbound)
            else:
                logger.warning(f"Failed to convert link: {link}")

        if not converted_outbounds:
            # Handle kasus jika tidak ada link valid yang dikonversi
            # Jika template sudah mengandung outbounds yang cukup, bisa tetap lanjut
            # Tapi jika tidak ada, ini mungkin error.
            # Kita bisa kembalikan config_data asli atau tambahkan pesan warning lebih spesifik.
            # Untuk saat ini, kita akan tambahkan outbounds default jika tidak ada konversi.
            logger.warning("Nggak ada link VPN valid yang dikonversi. Melanjutkan dengan outbounds template dan default.")


        # Simpan outbounds 'direct' dan 'dns' dari template jika ada
        # Lalu hapus dari list utama untuk diatur ulang posisinya
        default_outbounds = []
        outbounds_to_keep = []
        bypass_outbound_found = False
        dns_out_outbound_found = False

        for outbound in config_data["outbounds"]:
            if outbound.get("type") == "direct" and outbound.get("tag") == "bypass":
                default_outbounds.append(outbound)
                bypass_outbound_found = True
            elif outbound.get("type") == "dns" and outbound.get("tag") == "dns-out":
                default_outbounds.append(outbound)
                dns_out_outbound_found = True
            else:
                outbounds_to_keep.append(outbound)
        
        # Tambahkan outbound 'bypass' dan 'dns-out' jika belum ada di template
        # dengan struktur yang sesuai permintaan user
        if not bypass_outbound_found:
            default_outbounds.append({
                "type": "direct",
                "tag": "bypass"
            })
        if not dns_out_outbound_found:
            default_outbounds.append({
                "type": "dns",
                "tag": "dns-out"
            })


        # Gabungkan semua outbounds: yang baru dikonversi + yang dipertahankan + default outbounds
        # Pastikan outbounds yang dikonversi ada di paling atas
        # dan default outbounds (bypass, dns-out) di paling bawah
        final_outbounds = []
        final_outbounds.extend(converted_outbounds) # Akun VPN dikonversi ditaruh paling atas
        final_outbounds.extend(outbounds_to_keep) # Outbounds lain dari template
        final_outbounds.extend(default_outbounds) # 'bypass' dan 'dns-out' ditaruh paling bawah

        config_data["outbounds"] = final_outbounds

        # --- UPDATE REFERENSI UNTUK SELECTOR/URLTEST (DENGAN PENGECUALIAN) ---
        # Kumpulkan semua tag outbound yang baru (termasuk yang dikonversi)
        all_outbound_tags = [o["tag"] for o in final_outbounds if "tag" in o]
        logger.debug(f"All available outbound tags after conversion: {all_outbound_tags}")

        updated_ref_count = 0
        for outbound_selector in config_data["outbounds"]:
            current_selector_tag = outbound_selector.get("tag")
            
            # --- Pengecualian di sini! ---
            if current_selector_tag in EXCLUDED_SELECTOR_TAGS:
                logger.info(f"Melewati selector '{current_selector_tag}' karena ada di daftar pengecualian.")
                continue # Langsung lanjut ke selector berikutnya

            if (outbound_selector.get("type") == "selector" or \
                outbound_selector.get("type") == "urltest") and \
                "outbounds" in outbound_selector and \
                isinstance(outbound_selector["outbounds"], list):
                
                original_nested_outbounds_list = list(outbound_selector["outbounds"]) # Salin untuk perbandingan
                
                # Buat daftar outbounds baru untuk selector ini,
                # prioritaskan yang dikonversi, lalu tambahkan yang default/lainnya dari template
                new_nested_outbounds = []

                # Tambahkan hanya tag yang sudah dikonversi ke selector (jika ada)
                # Ini mengasumsikan selector ingin menyertakan semua node VPN
                for converted_outbound in converted_outbounds:
                    if converted_outbound["tag"] not in new_nested_outbounds:
                        new_nested_outbounds.append(converted_outbound["tag"])

                # Tambahkan tag 'bypass' dan 'dns-out' jika belum ada di selector dan memang ada
                # Asumsi: selector biasanya mengacu pada node VPN, direct, dan dns-out
                for default_o in default_outbounds:
                    if default_o["tag"] not in new_nested_outbounds:
                        new_nested_outbounds.append(default_o["tag"])

                # Tambahkan outbound lain yang ada di selector asli, kecuali yang sudah ditambahkan
                for original_tag in original_nested_outbounds_list:
                    if original_tag not in new_nested_outbounds and original_tag in all_outbound_tags:
                        new_nested_outbounds.append(original_tag)

                # Hanya update jika ada perubahan pada list outbounds nested
                if new_nested_outbounds != original_nested_outbounds_list:
                    outbound_selector["outbounds"] = new_nested_outbounds
                    updated_ref_count += 1
                    logger.debug(f"Updated selector '{current_selector_tag}'. New outbounds: {new_nested_outbounds}")
                else:
                    logger.debug(f"Selector '{current_selector_tag}' not updated (no changes).")
            else:
                logger.debug(f"Skipping non-selector item or malformed selector: {outbound_selector.get('tag', 'No Tag')} (Type: {type(outbound_selector)})\n{outbound_selector}")


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
    print("Mek, file ini adalah modul logika Sing-Box. Jalankan 'app.py' untuk UI-nya ya.")

                           
