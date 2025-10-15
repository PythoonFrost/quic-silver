# vis_time_vs_packets.py

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import os
from datetime import datetime

CSV_FILE = "final_quicMeta.csv"
SAVE_IMAGE_PATH = os.path.join(os.getcwd(), "final_quic_telemetry_timeseries.png")
REFRESH_INTERVAL_MS = 2000

fig, ax = plt.subplots()
plt.title("QUIC Flood Activity Over Time 📈")
plt.xlabel("Timestamp")
plt.ylabel("Total Packet Count (Delta)")
plt.xticks(rotation=45)
plt.grid(True)

def animate(i):
    try:
        df = pd.read_csv(CSV_FILE)
        if df.empty:
            return
        
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df_grouped = df.groupby('Timestamp')['Packet_Count'].sum()
        
        ax.clear()
        plt.title("QUIC Flood Activity Over Time 📈")
        plt.xlabel("Timestamp")
        plt.ylabel("Total Packet Count (Delta)")
        plt.xticks(rotation=45)
        plt.grid(True)

        ax.plot(df_grouped.index, df_grouped.values, marker='o', linestyle='-')
    except Exception as e:
        print(f"[Warning] {e}")

def on_close(event=None):
    try:
        fig.savefig(SAVE_IMAGE_PATH, dpi=300, bbox_inches='tight')
        print(f"[+] Saved graph at: {SAVE_IMAGE_PATH}")
    except Exception as e:
        print(f"[Error] Saving failed: {e}")

fig.canvas.mpl_connect('close_event', on_close)

ani = animation.FuncAnimation(fig, animate, interval=REFRESH_INTERVAL_MS)

try:
    print("[+] Visualization Running (Time vs Packets)... Ctrl+C to save and exit.")
    plt.show()
except KeyboardInterrupt:
    on_close()
    plt.close()
