import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

def plot_fase(csv_path: str, output_img: str):
    if not Path(csv_path).exists():
        print(f"File {csv_path} does not exist. Skipping.")
        return
        
    df = pd.read_csv(csv_path, sep=';', on_bad_lines='skip')
    if df.empty:
        print(f"No data in {csv_path}. Skipping.")
        return

    df['hora'] = df['timestamp'].str.extract(r'-(\d{2}:\d{2}:\d{2})')
    
    # Count occurrences per (Fase, hora)
    if 'Fase' in df.columns:
        hits = df.groupby(['hora', 'Fase']).size().unstack(fill_value=0)
    else:
        # Default if no 'Fase' column
        hits = df.groupby('hora').size().to_frame(name='freq')

    if hits.empty:
        return

    # Plot
    fig, ax = plt.subplots(figsize=(12, 6))
    hits.plot(kind='bar', width=0.8, ax=ax)
    
    ax.set_ylim(0, 8)
    ax.set_xlabel('Hora')
    ax.set_ylabel('Frecuencia')
    ax.set_title(f'Gráfico de frecuencia: {Path(csv_path).stem}')
    
    # Clean up x-axis ticks to avoid overlapping if there are too many
    n_ticks = len(hits.index)
    if n_ticks > 20:
        step = n_ticks // 20
        ax.set_xticks(range(0, n_ticks, step))
        ax.set_xticklabels(hits.index[::step], rotation=45, ha='right')
    else:
        plt.xticks(rotation=45, ha='right')
        
    plt.tight_layout()
    plt.savefig(output_img, dpi=600)
    plt.close()

def main():
    base_dir = Path(".")
    
    files_to_process = [
        ("alertas_clasificadas_fase_1_grafico.csv", "fase1.svg"),
        ("alertas_clasificadas_fase_2_grafico.csv", "fase2.svg"),
        ("alertas_clasificadas_fase_3_grafico.csv", "fase3.svg")
    ]
    
    for csv_file, out_file in files_to_process:
        csv_path = base_dir / csv_file
        out_path = base_dir / out_file
        print(f"Processing {csv_file} -> {out_file}")
        plot_fase(str(csv_path), str(out_path))

if __name__ == "__main__":
    main()
