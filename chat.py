
import argparse, socket, struct, threading, sys
from des import encrypt_ecb, decrypt_ecb

SHARED_KEY = b""  
def send_msg(sock, text):
    payload = encrypt_ecb(text.encode("utf-8"), SHARED_KEY)   
    sock.sendall(struct.pack(">I", len(payload)) + payload)   
    print(f"   [kirim] plaintext : {text}")
    print(f"   [kirim] ciphertext: {payload.hex()}")

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ditutup")
        buf += chunk
    return buf

def receiver_loop(sock, name):
    try:
        while True:
            (length,) = struct.unpack(">I", recv_exact(sock, 4))
            payload = recv_exact(sock, length)
            print(f"\n   [terima] ciphertext: {payload.hex()}")
            try:
                print(f"   [terima] plaintext : {decrypt_ecb(payload, SHARED_KEY).decode('utf-8')}")
            except Exception as e:
                print(f"   [terima] gagal dekripsi: {e}")
            print(f"{name} > ", end="", flush=True)
    except (ConnectionError, OSError):
        print("\nKoneksi terputus."); 
        import os; os._exit(0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["server", "client"])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", default=None, help="(opsional) key DES; jika kosong akan diminta lewat input")
    a = ap.parse_args()
    global SHARED_KEY
    key_text = a.key if a.key else input("Masukkan key DES (pre-shared): ")
    SHARED_KEY = key_text.encode("utf-8")
    if len(SHARED_KEY) != 8:
        print(f"[info] key {len(SHARED_KEY)} byte; DES memakai 8 byte: {SHARED_KEY[:8].decode(errors='replace')}")
    SHARED_KEY = SHARED_KEY[:8].ljust(8, b"\x00")

    if a.role == "server":
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", a.port)); srv.listen(1)
        print(f"Menunggu koneksi di port {a.port} ...")
        sock, addr = srv.accept(); print("Terhubung dengan", addr)
        name = "Receiver"
    else:
        sock = socket.create_connection((a.host, a.port))
        print("Terhubung ke", (a.host, a.port)); name = "Sender"

    threading.Thread(target=receiver_loop, args=(sock, name), daemon=True).start()
    print("Ketik pesan lalu Enter. Perintah: /key (ganti key), exit (keluar).")
    while True:
        text = input(f"{name} > ")
        if text.strip().lower() == "exit":
            break
        if text.startswith("/key"):
            new_key = text[4:].strip() or input("Masukkan key DES baru: ")
            SHARED_KEY = new_key.encode("utf-8")[:8].ljust(8, b"\x00")
            print(f"   [info] key diganti, DES memakai: {SHARED_KEY.decode(errors='replace')}")
            continue
        if text:
            send_msg(sock, text)
    sock.close()

if __name__ == "__main__":
    main()
