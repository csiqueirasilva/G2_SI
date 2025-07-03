#!/usr/bin/env python3
"""
mini_bruteforce.py – brute-force de IV AES-CBC com tqdm, checkpoint,
match_type configurável, escolha de derivação de chave (raw, hash1 ou hash2)
e prompt interativo em caso de “partial hit”.

Uso básico:
    python mini_bruteforce.py SEED "trecho plaintext" HEXCIPHER [opções]

Opções novas:
    --key-mode {raw,hash1,hash2}
        raw   = usa seed direta (pad/truncate para 16 bytes)
        hash1 = SHA-1(seed)[:16]
        hash2 = SHA-1(SHA-1(seed))[:16]        ← padrão (duplo SHA-1)
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

IV_PAD    = 16           # cada IV é string decimal com zero-padding p/ 16 bytes
CHK_EVERY = 5_000_000    # grava checkpoint a cada N IVs processados
BATCH     = 10           # frequência de update no counter compartilhado

# ---------------------------------------------------------------------------
# utilidades
# ---------------------------------------------------------------------------

def derive_key(seed: str, mode: str = 'raw') -> bytes:
    """Gera chave AES-128 (16 bytes) segundo *mode*.

    raw   → seed direta, padding 0x00 à direita (ou truncate) para 16 bytes
    hash1 → SHA-1(seed)[:16]
    hash2 → SHA-1(SHA-1(seed))[:16]
    """
    if mode.startswith('hash'):
        h = hashlib.sha1(seed.encode()).digest()
        if mode == 'hash2':
            h = hashlib.sha1(h).digest()
        return h[:16]

    # modo raw (default)
    k = seed.encode()
    return k.ljust(16, b'\x00')[:16]

# Valor compartilhado entre os workers
counter = None  # será inicializado no init_worker

def init_worker(shared_counter):
    global counter
    counter = shared_counter

# ---------------------------------------------------------------------------
# worker
# ---------------------------------------------------------------------------

def worker(args):
    """
    Processo que percorre IVs na forma: start, start+step, … < max_iv
    Retorna (iv_str, plaintext, exact_bool) em caso de sucesso ou None.
    exact_bool = True  → pt == known (correspondência exata)
    exact_bool = False → apenas contém/startswith, conforme --match
    """
    (seed, known, ct, start, step, max_iv, match_type, key_mode) = args
    key       = derive_key(seed, key_mode)
    known_b   = known                   # trecho conhecido (bytes)
    processed = 0                       # IVs testados desde o último flush

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

        # 2) comparação com o trecho conhecido
        exato = pt == known_b
        parcial_ok = (match_type == 'prefix'   and pt.startswith(known_b)) or \
                     (match_type == 'contains' and known_b in pt)

        if not (exato or parcial_ok):
            # não serve
            processed += 1
            if processed == BATCH:
                with counter.get_lock():
                    counter.value += processed
                processed = 0
            continue

        # 3) SUCESSO (exato ou parcial) -------------------------------
        if processed:
            with counter.get_lock():
                counter.value += processed
        return iv.decode(), pt, exato

    # fim do range → não achou neste worker
    if processed:
        with counter.get_lock():
            counter.value += processed
    return None

# ---------------------------------------------------------------------------
# função principal
# ---------------------------------------------------------------------------

def brute(seed, known, ct, digits, start_index=0, resume=0,
          match_type='contains', key_mode='raw'):
    """Executa brute-force de start_index até 10**digits-1.
    Retorna (iv_str, plaintext, exato) ou (None, None, None)."""
    max_iv  = 10 ** digits
    nprocs  = cpu_count()
    base    = max(start_index, resume)  # ponto inicial efetivo

    print(f"[*] Brute-forcing {base:,}…{max_iv-1:,} ({digits} dígitos)")
    print(f"[*]   usando {nprocs} processos | match={match_type} | key_mode={key_mode}")

    shared_counter = Value('Q', base)
    tasks = [
        (seed, known, ct, base + i, nprocs, max_iv, match_type, key_mode)
        for i in range(nprocs)
    ]

    start_t = last_eta_t = time.time()
    last_chk = base
    found = None

    with Pool(nprocs, initializer=init_worker, initargs=(shared_counter,)) as pool, \
         tqdm(total=max_iv, initial=base, dynamic_ncols=True, unit='IVs') as pbar:

        results = [pool.apply_async(worker, (t,)) for t in tasks]

        while True:
            # progresso global
            with shared_counter.get_lock():
                done = shared_counter.value
            if done != pbar.n:
                pbar.update(done - pbar.n)

            # ETA/speed a cada ~1 s
            now = time.time()
            if now - last_eta_t >= 1:
                speed = (done - base) / (now - start_t + 1e-9)
                eta   = (max_iv - done) / (speed + 1e-9)
                pbar.set_postfix_str(f"ETA {eta:,.0f}s | {speed:,.0f} IV/s")
                last_eta_t = now

            # checkpoint periódico
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
                        found = res            # (iv, pt, exato)
                        pool.terminate()       # encerra demais workers
                        break
            if found or not results:
                break

            time.sleep(0.01)

    return found if found else (None, None, None)

# ---------------------------------------------------------------------------
# CLI / loop interativo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Brute-force de IV AES-CBC com trecho conhecido do plaintext')
    parser.add_argument('seed')
    parser.add_argument('known',
                        help='trecho conhecido do plaintext (prefixo ou substring)')
    parser.add_argument('cipher_hex',
                        help='ciphertext em hex (IV não incluso)')
    parser.add_argument('-d', '--digits', type=int, default=16,
                        help='dígitos do IV (default: 16 ⇒ 10¹⁶)')
    parser.add_argument('-s', '--start-index', type=int, default=0,
                        help='IV inicial (offset) para começar a busca')
    parser.add_argument('--match', choices=['contains', 'prefix'],
                        default='contains',
                        help='modo de comparação com o plaintext conhecido '
                             '(default: contains)')
    parser.add_argument('--key-mode', choices=['raw', 'hash1', 'hash2'],
                        default='hash2',
                        help='raw   = seed direta (pad/truncate p/16)\n'
                             'hash1 = SHA-1(seed)[:16]\n'
                             'hash2 = SHA-1(SHA-1(seed))[:16]  [padrão]')
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
        resume_from = args.start_index  # start-index sobrescreve checkpoint

    # ---- loop principal (pode reiniciar após partial hit) ------------
    current_start = max(args.start_index, resume_from)

    while current_start < 10 ** args.digits:
        iv, pt, exato = brute(args.seed, args.known.encode(), ct,
                              args.digits, current_start, 0,
                              args.match, args.key_mode)

        if iv is None:
            print('\nNenhum IV no intervalo.')
            break

        # mostra resultado
        print(f"\n>>> Possível IV encontrado: {iv}")
        try:
            print(pt.decode(errors='ignore'))
        except Exception:
            print(pt)

        if exato:
            print("\n[*] O plaintext corresponde exatamente ao trecho conhecido.")
            break  # fim da busca

        # pergunta se continua
        resp = input("\n[?] Continuar procurando por outros IVs? [s/N] ").strip().lower()
        if resp not in ('s', 'y', 'yes'):
            break  # usuário não quer continuar

        # continua busca a partir do próximo IV
        current_start = int(iv) + 1
        print(f"\n[*] Reiniciando busca a partir do IV {current_start:,}…")

    print("\n[*] Fim.")
