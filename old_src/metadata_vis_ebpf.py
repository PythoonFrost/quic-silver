import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import os

# === Step 1: Load  data ===
csv_file = "final_quicMeta.csv"
df = pd.read_csv(csv_file)

# === Step 2: Convert Timestamp column to datetime ===
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# === Step 3: Group by Anomaly Type and Timestamp ===
flood_df = df[df['Anomaly_Flag'] == 'Flood']
loris_df = df[df['Anomaly_Flag'] == 'Loris']
normal_df = df[df['Anomaly_Flag'] == 'Normal']

flood_counts = flood_df.groupby(pd.Grouper(key='Timestamp', freq='1S')).size()
loris_counts = loris_df.groupby(pd.Grouper(key='Timestamp', freq='1S')).size()
normal_counts = normal_df.groupby(pd.Grouper(key='Timestamp', freq='1S')).size()

# === Step 4: Plot ===
plt.figure(figsize=(15, 8))

plt.plot(flood_counts.index, flood_counts.values, marker='o', linestyle='-', color='red', label='Flood')
plt.plot(loris_counts.index, loris_counts.values, marker='x', linestyle='--', color='blue', label='Loris')
plt.plot(normal_counts.index, normal_counts.values, marker='.', linestyle='-', color='green', label='Normal')

plt.title('QUIC Packet Timing Visualization (Flood vs Loris vs Normal)')
plt.xlabel('Time')
plt.ylabel('Packets per second')

plt.xticks(rotation=45)
plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

plt.legend()
plt.grid(True)
plt.tight_layout()

# === Step 5: Handle save on close ===
save_path = os.path.expanduser("~/Desktop/quic_packet_timing_plot.png")

def save_on_close(event):
    plt.savefig(save_path)
    print(f"\n[+] Graph saved successfully at {save_path}")

# Connect close event
plt.gcf().canvas.mpl_connect('close_event', save_on_close)

# Show plot
try:
    plt.show()
except KeyboardInterrupt:
    print("\n[+] Script interrupted, plot closed.")
