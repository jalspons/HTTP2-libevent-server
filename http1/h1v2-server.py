import asyncio
import ssl


@asyncio.coroutine
def client_connected(reader, writer):
    print(writer.get_extra_info("socket").getpeercert())
    while True:
        file_data = f.read(32768) # use an appropriate chunk size
        if file_data is None or len(file_data) == 0:
            break
        writer.write(file_data) 
    f.close()
    writer.close()

sslcontext = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
sslcontext.verify_mode = ssl.CERT_REQUIRED
sslcontext.load_cert_chain(certfile="host.crt", keyfile="host.key")

loop = asyncio.get_event_loop()
asyncio.async(asyncio.start_server(client_connected, "127.0.0.1", 8080, ssl=sslcontext))

loop.run_forever()
