import pandas as pd
import matplotlib.pyplot as plt

# Load CSV
df = pd.read_csv('final_quicMeta.csv')

# Separate anomaly types
flood_df = df[df['Anomaly_Flag'] == 'Flood']
loris_df = df[df['Anomaly_Flag'] == 'Loris']
normal_df = df[df['Anomaly_Flag'] == 'Normal']

plt.figure(figsize=(14, 8))

# Plot scatter points
plt.scatter(flood_df['Packet_Count'], flood_df['DCID_Count'], color='red', label='Flood', alpha=0.6, s=20)
plt.scatter(loris_df['Packet_Count'], loris_df['DCID_Count'], color='blue', label='Loris', alpha=0.6, s=20)
plt.scatter(normal_df['Packet_Count'], normal_df['DCID_Count'], color='green', label='Normal', alpha=0.6, s=20)

# --- Label only the last packet of each IP ---
for traffic_df, color in [(flood_df, 'red'), (loris_df, 'blue'), (normal_df, 'green')]:
    last_points = traffic_df.sort_values('Packet_Count').groupby('Source_IP').tail(1)
    for idx, row in last_points.iterrows():
        plt.text(row['Packet_Count'], row['DCID_Count']+10, row['Source_IP'], fontsize=6, color=color)

# Decorations
plt.xlabel('Packet Count')
plt.ylabel('DCID Count')
plt.title('QUIC Attack/Normal Visualization (Packet vs DCID Count)')
plt.legend()
plt.grid(True)

# Save automatically when closed
def on_close(event):
    plt.savefig('packet_vs_dcid_last_ip_labels.png')
    print("[+] Saved clean final graph with IP labels at end points ✅")

plt.gcf().canvas.mpl_connect('close_event', on_close)

plt.show()
