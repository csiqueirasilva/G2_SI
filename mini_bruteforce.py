#!/usr/bin/env python3
"""
mini_bruteforce.py – brute‑force de IV AES‑CBC com tqdm, checkpoint e suporte a
ponto de partida (--start-index).

* Gera um UUID por execução e o imprime logo no início.
* Usa esse UUID para nomear o arquivo de checkpoint / lock, evitando colisões
  entre execuções concorrentes.
* --start-index permite começar a busca em qualquer IV inteiro >= 0.
  Útil para dividir um espaço grande em "fatias" (ex.: cada máquina começa em
  um offset diferente) ou retomar a partir de um ponto conhecido.
"""
import os
import sys
import time
import uuid
import hashlib
import argparse
import re
from multiprocessing import Pool, cpu_count, Value
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from tqdm import tqdm

IV_PAD    = 16           # cada IV é string decimal com zero‑padding p/ 16 bytes
CHK_EVERY = 5_000_000    # grava checkpoint a cada N IVs processados
BATCH     = 10           # frequência de update no counter compartilhado

# ---------------------------------------------------------------------------
# utilidades
# ---------------------------------------------------------------------------

def derive_key(seed: str) -> bytes:
    """Deriva chave AES‑128 = SHA‑1(seed)[:16]"""
    return hashlib.sha1(seed.encode()).digest()[:16]

# Valor compartilhado entre os workers
counter = None  # será inicializado no init_worker

def init_worker(shared_counter):
    global counter
    counter = shared_counter

# ---------------------------------------------------------------------------
# worker
# ---------------------------------------------------------------------------

def worker(args):
    """Processo que percorre IVs na forma: start, start+step, … < max_iv"""
    seed, known, ct, start, step, max_iv = args
    key       = derive_key(seed)
    known_b   = known                    # plaintext completo
    processed = 0                        # IVs testados desde o último flush

    for iv_num in range(start, max_iv, step):
        iv = f"{iv_num:0{IV_PAD}d}".encode()

        # 1) decripta e remove padding; se padding inválido → segue
        try:
            dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
            pt  = unpad(dec, 16)
        except ValueError:
            processed += 1
            if processed == BATCH:
                with counter.get_lock():
                    counter.value += processed
                processed = 0
            continue

        # 2) plaintext precisa ser exatamente o esperado
        if pt != known_b:
            processed += 1
            if processed == BATCH:
                with counter.get_lock():
                    counter.value += processed
                processed = 0
            continue

        # 3) SUCESSO ---------------------------------------------
        if processed:
            with counter.get_lock():
                counter.value += processed
        return iv.decode(), pt

    # fim do range → não achou neste worker
    if processed:
        with counter.get_lock():
            counter.value += processed
    return None

# ---------------------------------------------------------------------------
# função principal
# ---------------------------------------------------------------------------

def brute(seed, known, ct, digits, start_index=0, resume=0):
    max_iv  = 10 ** digits
    nprocs  = cpu_count()
    base    = max(start_index, resume)  # ponto inicial efetivo

    print(f"[*] Brute‑forcing {base:,}…{max_iv-1:,} ({digits} dígitos)")
    print(f"[*]   usando {nprocs} processos")

    shared_counter = Value('Q', base)
    tasks = [
        (seed, known, ct, base + i, nprocs, max_iv)
        for i in range(nprocs)
    ]

    start_t = last_eta_t = time.time()
    last_chk = base
    found = None

    with Pool(nprocs, initializer=init_worker, initargs=(shared_counter,)) as pool, \
         tqdm(total=max_iv, initial=base, dynamic_ncols=True, unit='IVs') as pbar:

        results = [pool.apply_async(worker, (t,)) for t in tasks]

        while True:
            with shared_counter.get_lock():
                done = shared_counter.value
            if done != pbar.n:
                pbar.update(done - pbar.n)

            now = time.time()
            if now - last_eta_t >= 1:
                speed = (done - base) / (now - start_t + 1e-9)
                eta   = (max_iv - done) / (speed + 1e-9)
                pbar.set_postfix_str(f"ETA {eta:,.0f}s | {speed:,.0f} IV/s")
                last_eta_t = now

            if done - last_chk >= CHK_EVERY:
                with open(chkfile, 'w') as f:
                    f.write(str(done))
                last_chk = done

            # verifica resultados dos workers
            for r in list(results):
                if r.ready():
                    res = r.get()
                    results.remove(r)
                    if res:
                        found = res
                        pool.terminate()
                        break
            if found or not results:
                break

            time.sleep(0.01)

    return found if found else (None, None)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Brute‑force IV (AES‑CBC)')
    parser.add_argument('seed')
    parser.add_argument('known', help='plaintext completo a ser encontrado')
    parser.add_argument('cipher_hex', help='ciphertext em hex (IV não incluso)')
    parser.add_argument('-d', '--digits', type=int, default=9,
                        help='dígitos do IV (default: 9 ⇒ 10⁹)')
    parser.add_argument('-s', '--start-index', type=int, default=0,
                        help='IV inicial (offset) para começar a busca')
    args = parser.parse_args()

    # ---- UUID para esta execução -------------------------------------
    EXEC_ID = uuid.uuid4().hex
    print(f"[*] Execution ID: {EXEC_ID}")

    # ---- prepara ciphertext ------------------------------------------
    clean_hex = re.sub(r'[^0-9a-fA-F]', '', args.cipher_hex)
    try:
        ct = bytes.fromhex(clean_hex)
    except ValueError:
        sys.exit('Erro: ciphertext contém caracteres inválidos.')

    # ---- checkpoint (único por execução) -----------------------------
    chkfile = f'.iv.chk.{EXEC_ID}.d{args.digits}'
    resume_from = 0
    if os.path.exists(chkfile):
        try:
            resume_from = int(open(chkfile).read())
        except ValueError:
            resume_from = 0
    if resume_from and resume_from < args.start_index:
        # start-index sobrescreve checkpoint se for maior
        resume_from = args.start_index

    # ---- dispara brute‑force -----------------------------------------
    iv, pt = brute(args.seed, args.known.encode(), ct,
                   args.digits, args.start_index, resume_from)

    # ---- resultado ----------------------------------------------------
    if iv:
        print(f"\n>>> IV encontrado: {iv}")
        print(pt.decode(errors='ignore'))
    else:
        print('\nNenhum IV no intervalo.')
