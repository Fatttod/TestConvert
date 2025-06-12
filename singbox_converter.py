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
            "flow": query_params.get('flow', [''])[0], # for XTLS
            "host": query_params.get('host', [''])[0], # For websocket host
            "path": query_params.get('path', [''])[0]  # For websocket path
        }
        
        for key in ["sni", "alpn", "fp", "flow", "host", "path"]:
            if config[key] == '':
                config[key] = None

        logger.debug(f"Successfully parsed Trojan link: {host}")
        return config
    except Exception as e:
        logger.error(f"Error parsing Trojan link for {trojan_link[:50]}...: {e}")
        return None

# --- FUNGSI KONVERSI UTAMA KE SING-BOX (INI YANG DIPANGGIL DARI app.py) ---
def process_singbox_config(vpn_link):
    try:
        # Baca template dari singbox-template.txt (asumsi di direktori yang sama)
        current_dir = os.path.dirname(__file__)
        template_path = os.path.join(current_dir, "singbox-template.txt")
        try:
            with open(template_path, "r") as f:
                template_content = f.read()
            logger.info(f"Successfully read template from {template_path}")
        except FileNotFoundError:
            logger.error(f"Template file not found: {template_path}")
            return {"status": "error", "message": f"Error: Template 'singbox-template.txt' tidak ditemukan. Pastikan file ini ada di repositori yang sama dengan singbox_converter.py."}
        except Exception as e:
            logger.error(f"Error reading template file: {e}")
            return {"status": "error", "message": f"Error: Gagal membaca template: {e}"}

        # --- Link Parsing ---
        parsed_config = None
        protocol_type = None

        if "vmess://" in vpn_link:
            parsed_config = parse_vmess_link(vpn_link)
            if parsed_config:
                protocol_type = "vmess"
            else:
                return {"status": "error", "message": "Failed to parse VMess link. Check format."}
        elif "vless://" in vpn_link:
            parsed_config = parse_vless_link(vpn_link)
            if parsed_config:
                protocol_type = "vless"
            else:
                return {"status": "error", "message": "Failed to parse VLESS link. Check format."}
        elif "trojan://" in vpn_link:
            parsed_config = parse_trojan_link(vpn_link)
            if parsed_config:
                protocol_type = "trojan"
            else:
                return {"status": "error", "message": "Failed to parse Trojan link. Check format."}
        else:
            return {"status": "error", "message": "Unsupported VPN link type. Only VMess, VLESS, or Trojan are supported."}

        # --- Konversi ke Sing-Box (Placeholder Replacement) ---
        output_config = template_content

        # Common replacements
        output_config = output_config.replace("__OUTBOUND_TAG__", f'"{protocol_type}-out"')

        # Protocol-specific replacements
        if protocol_type == "vmess":
            output_config = output_config.replace("__PROTOCOL_TYPE__", "vmess")
            output_config = output_config.replace("__SERVER_ADDRESS__", json.dumps(parsed_config.get('add', '')))
            output_config = output_config.replace("__SERVER_PORT__", str(parsed_config.get('port', 443)))
            output_config = output_config.replace("__VMESS_UUID__", json.dumps(parsed_config.get('id', '')))
            output_config = output_config.replace("__VMESS_ALTERID__", str(parsed_config.get('aid', 0)))
            output_config = output_config.replace("__VMESS_SECURITY__", json.dumps(parsed_config.get('scy', 'auto')))
            output_config = output_config.replace("__NETWORK_TYPE__", json.dumps(parsed_config.get('net', 'tcp')))
            output_config = output_config.replace("__TLS_STATUS__", str("true" if parsed_config.get('tls', '') == 'tls' else "false"))
            output_config = output_config.replace("__SNI__", json.dumps(parsed_config.get('sni', parsed_config.get('host', '')) if 'tls' in parsed_config else ""))
            output_config = output_config.replace("__WS_PATH__", json.dumps(parsed_config.get('path', '')))
            output_config = output_config.replace("__WS_HEADERS__", json.dumps({"Host": parsed_config.get('host', '')}) if parsed_config.get('net', '') == 'ws' and parsed_config.get('host', '') else "{}")
            output_config = re.sub(r"__VLESS_UUID__|__VLESS_FLOW__|__VLESS_SECURITY__", "", output_config)
            output_config = re.sub(r"__TROJAN_PASSWORD__|__TROJAN_FLOW__", "", output_config)

        elif protocol_type == "vless":
            output_config = output_config.replace("__PROTOCOL_TYPE__", "vless")
            output_config = output_config.replace("__SERVER_ADDRESS__", json.dumps(parsed_config.get('address', '')))
            output_config = output_config.replace("__SERVER_PORT__", str(parsed_config.get('port', 443)))
            output_config = output_config.replace("__VLESS_UUID__", json.dumps(parsed_config.get('uuid', '')))
            output_config = output_config.replace("__VLESS_FLOW__", json.dumps(parsed_config.get('flow', '')) if parsed_config.get('flow') else "")
            output_config = output_config.replace("__VLESS_SECURITY__", json.dumps(parsed_config.get('security', 'none')))
            output_config = output_config.replace("__NETWORK_TYPE__", json.dumps(parsed_config.get('type', 'tcp')))
            output_config = output_config.replace("__TLS_STATUS__", str("true" if parsed_config.get('security', '') == 'tls' else "false"))
            output_config = output_config.replace("__SNI__", json.dumps(parsed_config.get('sni', parsed_config.get('host', '')) if parsed_config.get('security', '') == 'tls' else ""))
            output_config = output_config.replace("__WS_PATH__", json.dumps(parsed_config.get('path', '')) if parsed_config.get('type', '') == 'ws' else "")
            output_config = output_config.replace("__WS_HEADERS__", json.dumps({"Host": parsed_config.get('host', '')}) if parsed_config.get('type', '') == 'ws' and parsed_config.get('host', '') else "{}")
            output_config = output_config.replace("__ALPN__", json.dumps(parsed_config.get('alpn', '')) if parsed_config.get('alpn') else "")
            output_config = output_config.replace("__FLOW_FINGERPRINT__", json.dumps(parsed_config.get('fp', '')) if parsed_config.get('fp') else "")
            output_config = re.sub(r"__VMESS_UUID__|__VMESS_ALTERID__|__VMESS_SECURITY__", "", output_config)
            output_config = re.sub(r"__TROJAN_PASSWORD__|__TROJAN_FLOW__", "", output_config)

        elif protocol_type == "trojan":
            output_config = output_config.replace("__PROTOCOL_TYPE__", "trojan")
            output_config = output_config.replace("__SERVER_ADDRESS__", json.dumps(parsed_config.get('address', '')))
            output_config = output_config.replace("__SERVER_PORT__", str(parsed_config.get('port', 443)))
            output_config = output_config.replace("__TROJAN_PASSWORD__", json.dumps(parsed_config.get('password', '')))
            output_config = output_config.replace("__TROJAN_FLOW__", json.dumps(parsed_config.get('flow', '')) if parsed_config.get('flow') else "")
            output_config = output_config.replace("__NETWORK_TYPE__", json.dumps(parsed_config.get('type', 'tcp')))
            output_config = output_config.replace("__TLS_STATUS__", "true")
            output_config = output_config.replace("__SNI__", json.dumps(parsed_config.get('sni', parsed_config.get('host', '')) if parsed_config.get('sni') else ""))
            output_config = output_config.replace("__WS_PATH__", json.dumps(parsed_config.get('path', '')) if parsed_config.get('type', '') == 'ws' else "")
            output_config = output_config.replace("__WS_HEADERS__", json.dumps({"Host": parsed_config.get('host', '')}) if parsed_config.get('type', '') == 'ws' and parsed_config.get('host', '') else "{}")
            output_config = output_config.replace("__ALPN__", json.dumps(parsed_config.get('alpn', '')) if parsed_config.get('alpn') else "")
            output_config = output_config.replace("__FLOW_FINGERPRINT__", json.dumps(parsed_config.get('fp', '')) if parsed_config.get('fp') else "")
            output_config = re.sub(r"__VMESS_UUID__|__VMESS_ALTERID__|__VMESS_SECURITY__", "", output_config)
            output_config = re.sub(r"__VLESS_UUID__|__VLESS_FLOW__|__VLESS_SECURITY__", "", output_config)
        
        # Cleanup any remaining unused placeholders
        output_config = re.sub(r"__\w+__", "", output_config)

        # Bagian ini dari original singbox_converter.py lo untuk selector/urltest
        # Ini tidak perlu diubah secara signifikan kecuali jika lo punya selector yang kompleks di template
        # Misalnya, jika lo ingin menambahkan outbound yang baru dikonversi ke selector yang sudah ada di template
        # Jika template lo sederhana, bagian ini mungkin tidak terlalu berpengaruh atau bisa dihilangkan
        # Untuk kasus lo yang cuma timpa sfa.txt/tsel-sfa.txt, mungkin bagian ini tidak begitu krusial
        
        # Gua pertahankan struktur output yang sama dengan singbox_converter.py lo
        return {
            "status": "success", 
            "message": "Konfigurasi Sing-Box baru sudah dibuat.",
            "config_content": new_config_content, # Ganti ini dengan new_config_content
        }

    except Exception as e:
        logger.error(f"Error during Sing-Box conversion: {e}", exc_info=True)
        return {"status": "error", "message": f"Terjadi error yang nggak terduga saat konversi Sing-Box: {e}"}

if __name__ == '__main__':
    # Ini cuma buat debugging lokal singbox_converter.py secara terpisah
    # print("Mek, file ini adalah modul logika Sing-Box. Jalankan 'app.py' untuk UI-nya ya...")
    # Contoh penggunaan langsung (hapus atau komentar ini di produksi)
    # vmess_example = "vmess://eyJhZGQiOiAidjIuYm9kLmluIiwgImFpZCI6ICIwIiwgImhvc3QiOiAiY2RuLnJvbWFuLmNuIiwgImlkIjogImE3ZTdhMTIwLTk2ZDYtNDEyZC1hZDdjLTAwNjMwZjIyZmQxOCIsICJuZXQiOiAid3MiLCAicGF0aCI6ICIvc2VydmVyIiwgInBvcnQiOiAiNDQzIiwgInBzIjogInRlc3QtVm1lc3MiLCAic2N5IjogImF1dG8iLCAic25pIjogImNkbi5yb21hbi5jbiIsICJ0bHMiOiAidGxzIn0="
    # result = process_singbox_config(vmess_example)
    # if result["status"] == "success":
    #     print(result["config_content"])
    # else:
    #     print(result["message"])
    pass
    
