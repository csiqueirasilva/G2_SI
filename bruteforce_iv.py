#!/usr/bin/env python3
# mini_bruteforce.py – brute-force de IV AES-CBC com tqdm + checkpoint seguro
import os, sys, time, hashlib, argparse, re
from multiprocessing import Pool, cpu_count, Value
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from tqdm import tqdm

IV_PAD    = 16            # "0000000000000005"
CHK_EVERY = 5_000_000     # grava a cada N IVs
BATCH     = 10            # workers avisam contador global a cada N IVs

counter = None            # (global nos workers)

# ----------------------------------------------------------------------
def derive_key(seed: str) -> bytes:
    return hashlib.sha1(seed.encode()).digest()[:16]

def init_worker(shared_counter):
    global counter
    counter = shared_counter

def worker(args):
    seed, known, ct, start, step, max_iv = args
    key       = derive_key(seed)
    known_b   = known
    processed = 0

    for iv_num in range(start, max_iv, step):
        iv = f'{iv_num:0{IV_PAD}d}'.encode()
        try:
            pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
        except ValueError:
            pt = None

        if pt and known_b in pt:
            if processed:
                with counter.get_lock():
                    counter.value += processed
            return iv.decode(), pt

        processed += 1
        if processed == BATCH:
            with counter.get_lock():
                counter.value += processed
            processed = 0

    if processed:
        with counter.get_lock():
            counter.value += processed
    return None

def brute(seed, known, ct, digits, resume=0):
    max_iv = 10 ** digits
    nprocs = cpu_count()
    print(f'[*] Brute-forcing 0…{max_iv-1:,} ({digits} dígitos) com {nprocs} processos')

    shared_counter = Value('Q', resume)
    tasks = [(seed, known, ct, i + resume, nprocs, max_iv) for i in range(nprocs)]

    start_t = last_eta_t = time.time()
    last_chk = resume
    found = None

    with Pool(nprocs, initializer=init_worker, initargs=(shared_counter,)) as pool, \
         tqdm(total=max_iv, initial=resume, dynamic_ncols=True, unit='IVs') as pbar:

        results = [pool.apply_async(worker, (t,)) for t in tasks]

        while True:
            with shared_counter.get_lock():
                done = shared_counter.value
            if done != pbar.n:
                pbar.update(done - pbar.n)

            now = time.time()
            if now - last_eta_t >= 1:
                speed = (done - resume) / (now - start_t + 1e-9)
                eta   = (max_iv - done) / (speed + 1e-9)
                pbar.set_postfix_str(f"ETA {eta:,.0f}s | {speed:,.0f} IV/s")
                last_eta_t = now

            if done - last_chk >= CHK_EVERY:
                with open(chkfile, 'w') as f:
                    f.write(str(done))
                last_chk = done

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

            time.sleep(0.05)

    return found if found else (None, None)

# ----------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Brute-force IV (AES-CBC) com tqdm')
    parser.add_argument('seed')
    parser.add_argument('known', help='sequência presente no plaintext')
    parser.add_argument('cipher_hex', help='ciphertext em hex (espaços são ignorados)')
    parser.add_argument('-d', '--digits', type=int, default=9,
                        help='dígitos do IV (default: 9 ⇒ 10⁹)')
    args = parser.parse_args()

    # --- limpa qualquer coisa que não seja 0-9 a-f A-F ---
    clean_hex = re.sub(r'[^0-9a-fA-F]', '', args.cipher_hex)
    try:
        ct = bytes.fromhex(clean_hex)
    except ValueError:
        sys.exit('Erro: ciphertext contém caracteres inválidos.')

    chkfile = f'.iv.chk.d{args.digits}'
    resume_from = 0
    if os.path.exists(chkfile):
        try:
            resume_from = int(open(chkfile).read())
        except ValueError:
            resume_from = 0
    if resume_from >= 10 ** args.digits:
        print('[*] Checkpoint fora do intervalo — começando do zero')
        os.remove(chkfile)
        resume_from = 0

    iv, pt = brute(args.seed, args.known.encode(), ct, args.digits, resume_from)

    if iv:
        print(f'\n>>> IV encontrado: {iv}')
        print(pt.decode(errors='ignore'))
        if os.path.exists(chkfile):
            os.remove(chkfile)
    else:
        print('\nNenhum IV no intervalo.')
