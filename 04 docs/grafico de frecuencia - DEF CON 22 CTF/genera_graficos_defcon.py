import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

def plot_dia(csv_path: str, output_img: str, dia_num: int):
    if not Path(csv_path).exists():
        print(f"File {csv_path} does not exist. Skipping.")
        return
        
    df = pd.read_csv(csv_path, sep=';', on_bad_lines='skip')
    if df.empty:
        print(f"No data in {csv_path}. Skipping.")
        return

    df['horas'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.dropna(subset=['horas'])
    
    # Resample to 15 mins counts
    hits = df.set_index('horas').resample('15min').size().to_frame(name='freq')

    if hits.empty:
        return

    # Format the index as string for x-axis
    hits.index = hits.index.strftime('%Y-%m-%d %H:%M')

    fig, ax = plt.subplots(figsize=(12, 6))
    hits.plot(kind='bar', width=0.8, ax=ax, color='#2693de', legend=False)
    
    ax.set_ylim(0, 1700)
    ax.set_xlabel('Hora')
    ax.set_ylabel('Ataques')
    ax.set_title('DEF CON 22 CTF\nSubred PPP')
    
    # Configure ticks
    n_ticks = len(hits.index)
    if n_ticks > 20:
        step = n_ticks // 20
        ax.set_xticks(range(0, n_ticks, step))
        ax.set_xticklabels(hits.index[::step], rotation=90, va='center', ha='right', fontsize=8)
    else:
        plt.xticks(rotation=90, va='center', ha='right', fontsize=8)
        
    # Disable minor grid
    ax.grid(False, which='minor')
    ax.grid(True, which='major', axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig(output_img, dpi=600)
    plt.close()

def main():
    base_dir = Path(".")
    
    files_to_process = [
        ("alertas_clasificadas_dia1.csv", "dia_1.svg", 1),
        ("alertas_clasificadas_dia2.csv", "dia_2.svg", 2),
        ("alertas_clasificadas_dia3.csv", "dia_3.svg", 3)
    ]
    
    for csv_file, out_file, d in files_to_process:
        csv_path = base_dir / csv_file
        out_path = base_dir / out_file
        print(f"Processing {csv_file} -> {out_file}")
        plot_dia(str(csv_path), str(out_path), d)

if __name__ == "__main__":
    main()
