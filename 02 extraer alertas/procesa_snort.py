import subprocess
import shutil
from pathlib import Path

def process_pcaps():
    print("Intentando detener servicio snort (si existe)...")
    try:
        subprocess.run(["service", "snort", "stop"], capture_output=True)
    except FileNotFoundError:
        # En entornos Docker minimalistas 'service' puede no existir
        pass

    #ajustar segun OS
    log_snort = Path("/var/log/snort/snort.log")
    alert_csv = Path("/var/log/snort/alert.csv")

    pcap_files = list(Path(".").glob("*.pcap"))
    
    if not pcap_files:
        print("No se encontraron archivos .pcap en el directorio actual.")
        return

    for pcap_file in pcap_files:
        print(f"Procesando: {pcap_file.name}")
        destino = pcap_file.stem
        
        log_snort.unlink(missing_ok=True)
        alert_csv.unlink(missing_ok=True)
        
        subprocess.run(["snort", "-c", "/etc/snort/snort.conf", "-r", str(pcap_file), "-q"])
        
        if log_snort.exists():
            shutil.move(str(log_snort), f"snort_{destino}.log")
        if alert_csv.exists():
            shutil.move(str(alert_csv), f"alert_{destino}.csv")

if __name__ == '__main__':
    process_pcaps()
