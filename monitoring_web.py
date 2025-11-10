import os
import re
import google.generativeai as genai
import requests
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# --- 1. KONFIGURASI WEB MONITOR ---
# (Pastikan ini sesuai dengan server Anda)
LOG_FILE_PATH = '/var/log/nginx/access.log' # GANTI JIKA ANDA PAKAI APACHE
TIME_WINDOW_MINUTES = 5
FAILURE_THRESHOLD = 1 # 1 kali serangan SQLi saja sudah bahaya

# Kunci API (Bisa pakai yang sama)
GEMINI_API_KEY = 'AIzaSyB313YmSSuxbSOAyROB47mDIcAM4wAuwFw'  
FONNTE_API_TOKEN = 'dYQYc6sh8isQV5riYk72'     
YOUR_PHONE_NUMBER = '6282399803221'

# --- POLA REGEX BARU UNTUK SERANGAN WEB ---
# Pola ini mencari IP, Timestamp, dan kata kunci SQLi/LFI
# CATATAN: Ini adalah pola dasar dan mungkin perlu disesuaikan
WEB_ATTACK_PATTERN = re.compile(
    # Grup 1: IP Address (mis: 123.45.67.89)
    r'([\d\.]+) - - '
    # Grup 2: Timestamp (mis: [10/Nov/2025:15:30:01 +0000])
    r'\[(.*?)\] '
    # Mencari URL yang mengandung pola serangan
    # (SELECT, UNION, ' OR ', ../.., /etc/passwd)
    r'".*?(SELECT\s|UNION\s|\'\s*OR\s*\'1\'=\'1\'|\.\./\.\./|\/etc\/passwd).*?"'
)

# --- 2. FUNGSI API (GEMINI & FONNTE) ---
# (Fungsi setup_gemini dan send_whatsapp_notification bisa sama persis)

def setup_gemini():
    """Mengkonfigurasi dan menginisialisasi model Gemini."""
    if not GEMINI_API_KEY:
        print("Error: GEMINI_API_KEY tidak ditemukan.")
        return None
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.5-pro')
        return model
    except Exception as e:
        print(f"Error konfigurasi Gemini: {e}")
        return None

def analyze_with_gemini_web(model, log_entries_str):
    """Mengirim log ke Gemini untuk analisis (prompt berbeda)."""
    if not model:
        return "Analisis Gemini tidak tersedia (model gagal dimuat)."

    prompt = f"""
    Analisis log server web berikut dari server saya. 
    Log ini tampaknya mengandung serangan SQL Injection atau LFI.
    Berikan ringkasan ancaman dalam satu paragraf singkat dan sarankan satu tindakan spesifik (misalnya, perintah UFW untuk memblokir IP).

    Log:
    {log_entries_str}
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error saat memanggil Gemini API: {e}")
        return f"Gagal menganalisis log. Serangan terdeteksi dari log berikut:\n{log_entries_str}"

def send_whatsapp_notification(message):
    """Mengirim pesan ke WhatsApp menggunakan Fonnte."""
    if not FONNTE_API_TOKEN or not YOUR_PHONE_NUMBER:
        print("Error: FONNTE_API_TOKEN atau YOUR_PHONE_NUMBER tidak ditemukan.")
        return
    url = "https://api.fonnte.com/send"
    payload = {'target': YOUR_PHONE_NUMBER,'message': message,}
    headers = {'Authorization': FONNTE_API_TOKEN}
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status() 
        print(f"Notifikasi WhatsApp (WEB) terkirim ke {YOUR_PHONE_NUMBER}.")
    except requests.exceptions.RequestException as e:
        print(f"Error mengirim notifikasi Fonnte: {e}")

# --- 3. FUNGSI UTAMA (MAIN) ---

def parse_log_time_web(timestamp_str):
    """Mengubah format waktu log web (Nginx/Apache) ke objek datetime."""
    # timestamp_str akan terlihat seperti: '10/Nov/2025:15:30:01 +0000'
    # Kita perlu membuatnya sadar zona waktu (aware)
    log_time = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
    return log_time


def main():
    print(f"Memulai monitor Web Attack pada {datetime.now()}...")
    gemini_model = setup_gemini()
    
    # Ambil waktu sekarang dengan zona waktu UTC
    time_threshold = datetime.now(timezone.utc) - timedelta(minutes=TIME_WINDOW_MINUTES)
    
    ip_attacks = defaultdict(int)
    ip_log_entries = defaultdict(list)

    try:
        with open(LOG_FILE_PATH, 'r') as f:
            for line in f:
                match = WEB_ATTACK_PATTERN.search(line)
                
                if match:
                    # Grup 1: IP, Grup 2: Timestamp
                    ip_address, timestamp_str = match.groups()[:2]
                    log_time = parse_log_time_web(timestamp_str)
                    
                    if log_time > time_threshold:
                        ip_attacks[ip_address] += 1
                        ip_log_entries[ip_address].append(line.strip())

    except FileNotFoundError:
        print(f"Error: File log tidak ditemukan di {LOG_FILE_PATH}")
        print("Pastikan path log (Nginx/Apache) sudah benar.")
        return
    except PermissionError:
        print(f"Error: Tidak memiliki izin untuk membaca {LOG_FILE_PATH}.")
        return
    except Exception as e:
        print(f"Error saat membaca file log: {e}")
        return

    # --- 4. PEMROSESAN HASIL & PEMBERITAHUAN ---
    
    print(f"Pengecekan selesai. Menemukan {len(ip_attacks)} IP penyerang dalam {TIME_WINDOW_MINUTES} menit terakhir.")
    
    alert_triggered = False
    for ip, count in ip_attacks.items():
        if count >= FAILURE_THRESHOLD:
            alert_triggered = True
            print(f"AMBANG BATAS TERLAMPAUI! IP: {ip}, Percobaan Serangan: {count}")
            
            log_str = "\n".join(ip_log_entries[ip])
            
            print(f"Mendapatkan analisis dari Gemini untuk IP {ip}...")
            analysis_result = analyze_with_gemini_web(gemini_model, log_str)
            
            header = f"🚨 PERINGATAN SERANGAN WEB (SQLi/LFI) 🚨\n\n"
            details = f"IP Asal: {ip}\nJumlah Percobaan: {count}\nRentang Waktu: {TIME_WINDOW_MINUTES} menit terakhir\n\n"
            gemini_section = f"🤖 Analisis Gemini:\n{analysis_result}"
            
            final_message = header + details + gemini_section
            
            send_whatsapp_notification(final_message)

    if not alert_triggered:
        print(f"Sistem web aman. Tidak ada serangan yang terdeteksi.")

if __name__ == "__main__":
    main()