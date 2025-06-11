import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Read the CSV file
df = pd.read_csv("final_quicMeta.csv")

# Filter for 1-RTT Packet packets and exclude server IP (192.168.58.128)
zero_rtt_data = df[(df["Packet_Type"] == "1-RTT Packet") & (df["Source_IP"] != "192.168.58.128")]

if zero_rtt_data.empty:
    print("No 1-RTT Packet packets detected in the data (excluding server IP).")
    exit()

# Convert Timestamp to datetime for plotting
zero_rtt_data = zero_rtt_data.copy()
zero_rtt_data["Timestamp"] = pd.to_datetime(zero_rtt_data["Timestamp"])
zero_rtt_data["Timestamp"] = (zero_rtt_data["Timestamp"] - zero_rtt_data["Timestamp"].min()).dt.total_seconds()  # Convert to seconds since start

# Plot 1: Line Plot for Cumulative 1-RTT Packet Packets Over Time Per IP
plt.figure(figsize=(12, 6))
unique_ips = zero_rtt_data["Source_IP"].unique()
colors = plt.cm.tab10(np.linspace(0, 1, len(unique_ips)))  # Simple color cycle

for idx, ip in enumerate(unique_ips):
    ip_data = zero_rtt_data[zero_rtt_data["Source_IP"] == ip]
    # Calculate cumulative count of 1-RTT Packet packets
    ip_data = ip_data.sort_values("Timestamp")
    ip_data["Cumulative_0RTT_Count"] = range(1, len(ip_data) + 1)
    plt.plot(ip_data["Timestamp"], ip_data["Cumulative_0RTT_Count"], label=f"IP {ip}", color=colors[idx])

plt.xlabel("Time (seconds since start)")
plt.ylabel("Cumulative 1-RTT Packet Packets")
plt.title("Cumulative 1-RTT Packet Packets Over Time by Source IP (Potential Loris, Excl. Server)")
plt.legend(loc="upper left", bbox_to_anchor=(1, 1))
plt.grid(True)
plt.tight_layout()
plt.savefig("zero_rtt_over_time_excl_server.png")
print("Line plot saved as zero_rtt_over_time_excl_server.png")

# Plot 2: Bar Chart for Total 1-RTT Packet Packets Per IP
plt.figure(figsize=(10, 6))
zero_rtt_counts = zero_rtt_data.groupby("Source_IP").size().sort_values(ascending=False)
bars = plt.bar(range(len(zero_rtt_counts)), zero_rtt_counts.values, color=plt.cm.Paired(np.linspace(0, 1, len(zero_rtt_counts))))
plt.xticks(range(len(zero_rtt_counts)), zero_rtt_counts.index, rotation=45)
plt.xlabel("Source IP")
plt.ylabel("Total 1-RTT Packet Packets")
plt.title("Total 1-RTT Packet Packets by Source IP (Potential Loris, Excl. Server)")

# Highlight the IP with the most 1-RTT Packet packets
max_idx = zero_rtt_counts.idxmax()
for i, bar in enumerate(bars):
    if zero_rtt_counts.index[i] == max_idx:
        bar.set_color("red")  # Highlight the highest in red
        plt.text(i, bar.get_height() + 0.5, f"{int(bar.get_height())}", ha="center", va="bottom", color="red")
    else:
        plt.text(i, bar.get_height() + 0.5, f"{int(bar.get_height())}", ha="center", va="bottom", color="black")

plt.grid(True, axis="y")
plt.tight_layout()
plt.savefig("zero_rtt_by_ip_excl_server.png")
print("Bar chart saved as zero_rtt_by_ip_excl_server.png")

plt.close("all")