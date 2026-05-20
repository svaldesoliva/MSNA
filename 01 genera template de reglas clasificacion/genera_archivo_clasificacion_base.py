import re
import pandas as pd
from pathlib import Path

#config inicial
RULES_DIR = Path("rules")
OUTPUT_FILE = "clasificacion_base.csv"

#destinos
DESTINOS_TIPO_1 = {"HOME_NET", "TELNET_SERVERS", "SMTP_SERVERS", "HTTP_SERVERS", "SQL_SERVERS", "any"}

# Expresiones regulares compiladas
REGEX_SID = re.compile(r'sid\s*:\s*(\d+)')
# Captura la dirección destino después de la flecha ->, ignorando el signo $ opcional
REGEX_DEST = re.compile(r'->\s+\$?([A-Za-z0-9_]+)')

def process_rule_file(filepath: Path) -> list[dict]:

    #Procesa un único archivo de reglas y retorna una lista de diccionarios
    #con los datos estructurados.

    records = []
    
    with filepath.open('r', encoding='latin-1', errors='replace') as file:
        for line in file:
            line = line.strip()

            if 'alert' not in line or '# alert' in line or 'sid:' not in line:
                continue
                
            sid_match = REGEX_SID.search(line)
            if not sid_match:
                continue
                
            sid = sid_match.group(1)
            
            # Determinar tipo_destino utilizando regex
            tipo_destino = 0
            dest_match = REGEX_DEST.search(line)
            
            if dest_match:
                destino = dest_match.group(1)
                if destino in DESTINOS_TIPO_1:
                    tipo_destino = 1
                elif destino == "EXTERNAL_NET":
                    tipo_destino = 2
                    
            #dejar limpio csv
            alerta_segura = line.replace(";", ",").replace("\n", ",").replace("\r", ",")
            
            records.append({
                "SID": sid,
                "Etapa": None,
                "Subetapa": None,
                "Observaciones": None,
                "tipo_destino": tipo_destino,
                "archivo": filepath.name,
                "alerta": alerta_segura
            })
            
    return records

def main():
    print(f"Buscando archivos .rules en el directorio '{RULES_DIR}'...")
    all_records = []
    
    rule_files = list(RULES_DIR.glob("*.rules"))
    
    for filepath in sorted(rule_files):
        records = process_rule_file(filepath)
        all_records.extend(records)
        print(f" - {filepath.name} procesado ({len(records)} reglas)")

    print("\nGenerando DataFrame y exportando resultados...")
    df = pd.DataFrame(all_records)
    
    if df.empty:
        print("No se encontraron reglas para procesar.")
        return

    df.to_csv(
        OUTPUT_FILE, 
        sep=';', 
        index=False, 
        encoding='utf-8',
        na_rep='' #para que los None queden como vacios
    )
    
    print(f"Se exportaron {len(df)} reglas en '{OUTPUT_FILE}'.")

if __name__ == '__main__':
    main()
