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

    # Ajustar segun OS
    log_snort = Path("/var/log/snort/snort.log")
    alert_csv = Path("/var/log/snort/alert.csv")


    # 1. Ajustar a carpeta con .pcap
    #base_dir = Path.home() / "MSNA/DEFCON200GB/DEFCON_CTF_22"
    base_dir = Path("/home/soc/MSNA/DEFCON200GB/DEFCON_CTF_22")



    # 2. Usamos rglob() para buscar recursivamente en todas las subcarpetas
    pcap_files = list(base_dir.rglob("*.pcap"))

    if not pcap_files:
        print(f"No se encontraron archivos .pcap en {base_dir}")
        return

    print(f"¡Se encontraron {len(pcap_files)} archivos .pcap para procesar!")

    for pcap_file in pcap_files:
        # Ahora imprimimos la ruta completa para saber en qué carpeta estamos
        print(f"Procesando: {pcap_file}")

        log_snort.unlink(missing_ok=True)
        alert_csv.unlink(missing_ok=True)

        # Ejecutamos Snort
        subprocess.run(["snort", "-c", "/etc/snort/snort.conf", "-r", str(pcap_file), "-q"])

        # 3. Guardamos los logs en la MISMA carpeta del archivo .pcap original
        # pcap_file.parent es la ruta a la carpeta donde vive el .pcap (ej: .../codered/)
        # pcap_file.stem es el nombre sin extension (ej: odered_00118_20140809194755)
        if log_snort.exists():
            destino_log = pcap_file.parent / f"snort_{pcap_file.stem}.log"
            shutil.move(str(log_snort), str(destino_log))
        if alert_csv.exists():
            destino_csv = pcap_file.parent / f"alert_{pcap_file.stem}.csv"
            shutil.move(str(alert_csv), str(destino_csv))


if __name__ == '__main__':
    process_pcaps()