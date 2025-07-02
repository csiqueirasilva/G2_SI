import sys
import hashlib
from Crypto.Cipher import AES
from multiprocessing import Pool, cpu_count

# configurações
IV_LENGTH = 16
MAX_IV = 10**IV_LENGTH  # 10^16

def derive_key(seed: str) -> bytes:
    """Deriva chave AES-128 via SHA-1(seed) e truncamento."""
    h = hashlib.sha1(seed.encode("utf-8")).digest()
    return h[:16]

def try_iv(args):
    """
    Função de worker para Pool:
      args = (seed, known_bytes, cipher_bytes, start, step)
    Cada processo faz:
      for iv_num in range(start, MAX_IV, step):
        testa IV = str(iv_num).zfill(16)
    """
    seed, known, cipher_bytes, start, step = args
    key = derive_key(seed)
    for iv_num in range(start, MAX_IV, step):
        iv_str = str(iv_num).zfill(IV_LENGTH)
        if iv_num % 1_000_000 == 0:
            print(f"[{start:02d}] Testando IV: {iv_str}")
        iv = iv_str.encode("ascii")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            pt = cipher.decrypt(cipher_bytes)
            pad = pt[-1]
            if 1 <= pad <= IV_LENGTH and pt.endswith(bytes([pad]) * pad):
                pt = pt[:-pad]
            else:
                continue
        except Exception:
            continue

        if known in pt:
            # retorna par (iv, texto) para sinalizar sucesso
            return iv_str, pt
    return None

def main():
    if len(sys.argv) != 4:
        print(f"Uso: python {sys.argv[0]} <seed> <\"Star Wars: Episode\"> <cipher_hex>")
        sys.exit(1)

    seed = sys.argv[1]
    known = sys.argv[2].encode("utf-8")
    cipher_bytes = bytes.fromhex(sys.argv[3])

    nprocs = cpu_count()
    print(f"Usando {nprocs} processos…")

    # prepara argumentos para cada processo: cada um pega IVs com passo = nprocs
    tasks = [(seed, known, cipher_bytes, i, nprocs) for i in range(nprocs)]

    with Pool(nprocs) as pool:
        for result in pool.imap_unordered(try_iv, tasks):
            if result:
                iv_str, plaintext = result
                print(f"\n>>> IV encontrado: {iv_str}")
                print(">>> Texto completo:")
                print(plaintext.decode("utf-8", "ignore"))
                pool.terminate()
                break
        else:
            print("Busca concluída, nenhum IV encontrou o trecho conhecido.")

if __name__ == "__main__":
    main()
