import time
from collections import defaultdict
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
from pygtail import Pygtail

#config inicial
ARCHIVO_ALERTAS = "alert.csv"
REGLAS_CLASIFICACION = "clasificacion.csv"
ARCHIVO_SID_NC = "sid_sin_clasificar.csv"
CARPETA_SALIDA = Path("salida/")
SERVICIO = False
SOLO_GRAFICAS = False

def init_sid_file():
    #Inicializa el archivo de SIDs no clasificados si no existe.
    if not Path(ARCHIVO_SID_NC).exists():
        with open(ARCHIVO_SID_NC, "w", encoding="utf-8") as f:
            f.write("SID;Cantidad\n")

def save_unclassified_sid(sid, unclassified_counts):
    #Suma y guarda un SID no clasificado en memoria (se volcará al final).
    unclassified_counts[sid] += 1

def load_classification() -> dict:
    #Carga las reglas de clasificación en un diccionario.
    clasificacion = {}
    
    if not Path(REGLAS_CLASIFICACION).exists():
        print(f"Error: No existe el archivo {REGLAS_CLASIFICACION}")
        return clasificacion
        
    df = pd.read_csv(REGLAS_CLASIFICACION, sep=";", encoding="latin-1", dtype=str)
    
    for _, row in df.iterrows():
        try:
            # Ignorar nulos y ceros
            if pd.isna(row['Etapa']) or str(row['Etapa']).strip() == '0':
                continue
                
            etapa = int(row['Etapa'])
            if not (1 <= etapa <= 4):
                continue
                
            subetapa = int(row['Subetapa']) if pd.notna(row['Subetapa']) and str(row['Subetapa']).strip() else 0
            
            clasificacion[str(row['SID'])] = {
                'Etapa': etapa,
                'Subetapa': subetapa,
                'tipo_destino': int(row['tipo_destino']) if pd.notna(row['tipo_destino']) else 0,
                'Alerta': str(row['alerta'])
            }
        except ValueError:
            continue
            
    return clasificacion

def generate_graphics(df_clasificadas: pd.DataFrame, out_dir: Path):
    #Genera todos los gráficos y reportes visuales usando Pandas, Matplotlib y Plotly.
    
    out_dir.mkdir(parents=True, exist_ok=True)
    
    if df_clasificadas.empty:
        print("No hay alertas para graficar.")
        return

    # Generar dataframes de indicadores
    # (Remoto, Etapa) -> count
    atacantes_pivot = df_clasificadas.pivot_table(index='Remoto', columns='Etapa', aggfunc='size', fill_value=0)
    atacantes_pivot.columns = [f'Etapa {c}' for c in atacantes_pivot.columns]
    # Asegurar que existan todas las etapas (1 a 4)
    for i in range(1, 5):
        if f'Etapa {i}' not in atacantes_pivot:
            atacantes_pivot[f'Etapa {i}'] = 0
            
    # (Local, Etapa) -> count
    hosts_pivot = df_clasificadas.pivot_table(index='Local', columns='Etapa', aggfunc='size', fill_value=0)
    hosts_pivot.columns = [f'Etapa {c}' for c in hosts_pivot.columns]
    for i in range(1, 5):
        if f'Etapa {i}' not in hosts_pivot:
            hosts_pivot[f'Etapa {i}'] = 0
            
    # Exportar los CSVs tal como lo hacía el original
    df_clasificadas.to_csv(out_dir / "alertas_clasificadas.csv", sep=";", index=False, encoding="latin-1")
    atacantes_pivot.to_csv(out_dir / "indicadores_atacantes.csv", sep=";", encoding="latin-1")
    hosts_pivot.to_csv(out_dir / "indicadores_hosts.csv", sep=";", encoding="latin-1")

    # Colores base
    colores_etapas = ["#6ec7ff", "#fedf8b", "#f46c43", "#d43d4f"]
    
    # Graficar atacantes
    alto_atacantes = max(2, (8 * len(atacantes_pivot)) // 11)
    
    fig, ax = plt.subplots(figsize=(10, alto_atacantes))
    atacantes_pivot.plot.barh(stacked=True, ax=ax, color=colores_etapas, logx=False, fontsize=6)
    ax.set_title('Ataques enviados por Host')
    ax.set_xlabel('Cantidad de ataques')
    ax.set_ylabel('Atacante')
    fig.savefig(out_dir / 'imagenResumenAtacante.svg', dpi=300, format='svg', bbox_inches='tight')
    plt.close(fig)

    # Graficar atacantes LOG
    fig, ax = plt.subplots(figsize=(10, alto_atacantes))
    atacantes_pivot.plot.barh(stacked=True, ax=ax, color=colores_etapas, logx=True, fontsize=6)
    ax.set_title('Ataques enviados por Host (escala logarítmica)')
    ax.set_xlabel('Cantidad de ataques')
    ax.set_ylabel('Atacante')
    fig.savefig(out_dir / 'imagenResumenAtacante_log.svg', dpi=300, format='svg', bbox_inches='tight')
    plt.close(fig)

    # Graficar hosts
    alto_hosts = max(2, (8 * len(hosts_pivot)) // 11)
    
    fig, ax = plt.subplots(figsize=(10, alto_hosts))
    hosts_pivot.plot.barh(stacked=True, ax=ax, color=colores_etapas, logx=False, fontsize=6)
    ax.set_title('Ataques recibidos por host')
    ax.set_xlabel('Cantidad de ataques')
    ax.set_ylabel('Hosts')
    fig.savefig(out_dir / 'imagenResumenHosts.svg', dpi=300, format='svg', bbox_inches='tight')
    plt.close(fig)

    # Graficar hosts LOG
    fig, ax = plt.subplots(figsize=(10, alto_hosts))
    hosts_pivot.plot.barh(stacked=True, ax=ax, color=colores_etapas, logx=True, fontsize=6)
    ax.set_title('Ataques recibidos por host (escala logarítmica)')
    ax.set_xlabel('Cantidad de ataques')
    ax.set_ylabel('Hosts')
    fig.savefig(out_dir / 'imagenResumenHosts_log.svg', dpi=300, format='svg', bbox_inches='tight')
    plt.close(fig)
    
def run_processing():
    # Ejecuta la lógica de lectura y clasificación, guardando estados en memoria.
    if not SOLO_GRAFICAS:
        if not SERVICIO:
            offset_path = Path(ARCHIVO_ALERTAS + ".offset")
            if offset_path.exists():
                offset_path.unlink()
                
        if not Path(ARCHIVO_ALERTAS).exists():
            print(f"Error: {ARCHIVO_ALERTAS} no encontrado.")
            return

        clasificacion = load_classification()
        init_sid_file()
        
        # Estados
        unclassified_counts = defaultdict(int)
        
        # Para lógica O(1) de etapas anteriores:
        # dict[(remoto, local)] -> { '3_1': bool, '3_count': int }
        history_state = defaultdict(lambda: {'3_1': False, '3_count': 0})
        
        resultados = []
        
        print(f"Procesando alertas desde {ARCHIVO_ALERTAS}...")
        try:
            for linea in Pygtail(ARCHIVO_ALERTAS):
                fila = [x.strip() for x in linea.split(",")]
                if len(fila) < 10:
                    continue
                    
                timestamp = fila[0]
                sid = fila[2]
                src = fila[6]
                dst = fila[8]
                
                # Clasificar
                if sid in clasificacion:
                    regla = clasificacion[sid]
                    etapa = regla['Etapa']
                    subetapa = regla['Subetapa']
                    
                    if regla['tipo_destino'] == 2:
                        remoto = dst
                        local = src
                    else:
                        remoto = src
                        local = dst
                        
                    # Lógica de estados heredada del script original
                    estado_previo = history_state[(remoto, local)]
                    
                    if etapa == 3 and subetapa == 1:
                        estado_previo['3_1'] = True
                    if etapa == 3:
                        estado_previo['3_count'] += 1
                        
                    if etapa == 2 and subetapa == 1:
                        if estado_previo['3_1']:
                            etapa = 4
                            subetapa = 10
                        elif estado_previo['3_count'] > 4:
                            etapa = 4
                            subetapa = 11

                    resultados.append({
                        'timestamp': timestamp,
                        'SID': sid,
                        'Etapa': etapa,
                        'Subetapa': subetapa,
                        'Remoto': remoto,
                        'Local': local,
                        'Alerta': regla['Alerta']
                    })
                else:
                    save_unclassified_sid(sid, unclassified_counts)
        except Exception as e:
            print(f"Error procesando el archivo de alertas: {e}")

        # Guardar SIDs sin clasificar
        if unclassified_counts:
            df_nc_old = pd.read_csv(ARCHIVO_SID_NC, sep=";") if Path(ARCHIVO_SID_NC).exists() else pd.DataFrame(columns=['SID', 'Cantidad'])
            df_nc_new = pd.DataFrame(list(unclassified_counts.items()), columns=['SID', 'Cantidad'])
            df_nc_combined = pd.concat([df_nc_old, df_nc_new]).groupby('SID', as_index=False).sum()
            df_nc_combined.to_csv(ARCHIVO_SID_NC, sep=";", index=False)
            
        # Volcar alertas a CSV si hay nuevas
        df_clasificadas = pd.DataFrame(resultados)
        CARPETA_SALIDA.mkdir(parents=True, exist_ok=True)
        if not df_clasificadas.empty:
            salida_path = CARPETA_SALIDA / "alertas_clasificadas.csv"
            # Si el archivo ya existe y estamos como servicio, hacemos append. Si no, lo pisamos (modo no servicio).
            mode = 'a' if (SERVICIO and salida_path.exists()) else 'w'
            header = not (SERVICIO and salida_path.exists())
            df_clasificadas.to_csv(salida_path, sep=";", encoding="latin-1", index=False, mode=mode, header=header)

    # Para graficar, recargamos el archivo completo para incluir todo el histórico
    alertas_file = CARPETA_SALIDA / "alertas_clasificadas.csv"
    if alertas_file.exists():
        df_todas = pd.read_csv(alertas_file, sep=";", encoding="latin-1")
        generate_graphics(df_todas, CARPETA_SALIDA)

def main():
    if SERVICIO:
        print("Modo servicio activado. Presiona Ctrl+C para salir.")
        while True:
            run_processing()
            time.sleep(5)
    else:
        run_processing()

if __name__ == '__main__':
    main()
