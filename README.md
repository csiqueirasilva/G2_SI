# Brute-Force IV (AES-CBC)

Este repositório contém um script (`mini_bruteforce.py`) que demonstra um ataque por força-bruta ao vetor de inicialização (IV) em AES-CBC **quando** o espaço de busca do IV é reduzido a strings numéricas ASCII zero-padded.

---

## 1  Preparação do ambiente Python

```bash
# criar e ativar ambiente virtual
python -m venv venv
# Windows PowerShell / cmd:
.\venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate

# instalar dependências mínimas
pip install tqdm pycryptodomex
```

> Usamos `pycryptodomex` para evitar conflitos com outras instalações do `Crypto`.

---

## 2  Uso rápido

O script agora suporta três modos de derivação de chave (`--key-mode`):

- `raw`   = seed direta (pad/truncate para 16 bytes)
- `hash1` = SHA-1(seed)[:16]
- `hash2` = SHA-1(SHA-1(seed))[:16]  ← **padrão**

E assume por padrão **16 dígitos** no IV (espaço até 10¹⁶), mas você pode mudar com `--digits`.

```bash
python mini_bruteforce.py \
SKYWALKER1980 \
"Star Wars: Episode" \
2c70e097ae1d4779068749584f1ec1a165fa8ce7c58fa02a9da9006dab69a0cb9d248d1c8b173817fddc948b40c927e98604fec781a035d173ec0793f2b19209f268f957f67db458c46c5e04a2ee997b3814424b2f782d75578fb49df79ad97736bdc93c102af9caf6cb6628deeaa8da \
--digits=9 --start-index 697000000 --match=prefix
```

No exemplo acima:

- `--digits=16` faz buscar de `0000000000000000` a `9999999999999999`.
- `--key-mode=hash2` usa duplo SHA-1 para derivar a chave (como “1472f95b9af2f031b075754adf1cbb7c”).
- `--match=prefix` interrompe ao encontrar plaintext cujo início bate com `"Star Wars: Episode"`.

Para um teste mínimo:

```bash
python mini_bruteforce.py TEST1 "EL" b5ffb348cb01ef862ea8df39e5b21206 --digits=2 --key-mode=hash1
```

---

## 3  Vetores de teste escalonados

Cada linha abaixo é independente — copie e cole no terminal. O `--start-index` ajuda a pular direto para perto do IV esperado.

### 3.1  IVs de 1 até 6 dígitos

```bash
# 1 dígito (0…9)
mini_bruteforce.py SEED5    "PLAINTEXT_5"    3887850d67ac20b0818a0c8aba30b502 --digits=1 --key-mode=hash1

# 2 dígitos (00…99)
mini_bruteforce.py SEED50   "PLAINTEXT_50"   cc6c6205a9183313a201be5f15e64ac9 --digits=2 --start-index=45 --key-mode=hash1

# 3 dígitos (000…999)
mini_bruteforce.py SEED500  "PLAINTEXT_500"  f31c4ce996ac3415d9a07397f34112f7 --digits=3 --start-index=490 --key-mode=hash1

# 4 dígitos
mini_bruteforce.py SEED5000 "PLAINTEXT_5000" 43e714cca0012d943df66b56e950b898  --digits=4 --start-index=4980 --key-mode=hash1

# 5 dígitos
mini_bruteforce.py SEED50000 "PLAINTEXT_50000" 85021974ddfe491c59a2bcf1fcfad335 --digits=5 --start-index=49800 --key-mode=hash1

# 6 dígitos
mini_bruteforce.py SEED500000 "PLAINTEXT_500000" a4bef1d9545c0404f8570c6790e48a8f40d6af9e96d3f5e905eed658ff59532a --digits=6 --start-index=495000 --key-mode=hash1
```

### 3.2  IVs de 7 até 9 dígitos

```bash
# 7 dígitos
mini_bruteforce.py SEED5000000   "PLAINTEXT_5000000"  fbca04103f4c35a28c174ff2e2e77736e4470cc265c65edae2b625174550099a --digits=7 --start-index=4900000 --key-mode=hash1

# 8 dígitos
mini_bruteforce.py SEED50000000  "PLAINTEXT_50000000"  0f14ce31985982bf2ce282455845a694094a86e5cf9bb483ac25bd4095883d29 --digits=8 --start-index=49000000 --key-mode=hash1

# 9 dígitos
mini_bruteforce.py SEED500000000 "PLAINTEXT_500000000" 9ce9be61f729e0eeb21502c7368a902426191239f73d9e61529b3a7cbe5a4c65 --digits=9 --start-index=495000000 --key-mode=hash1
```

Para cada execução você verá um **Execution ID (UUID)** e um checkpoint `.iv.chk.<UUID>.d<DIGITS>` que permite retomar em caso de interrupção.

---

## 4  Dividindo o trabalho em “fatias”

Para espaços grandes (ex.: `--digits=16`):

1. Em terminais separados, ajuste `--start-index` para 0, 10 000 000 000 000, 20 000 000 000 000, …
2. Cada processo trabalha em sua fatia e para automaticamente ao encontrar o IV ou esgotar o intervalo.

---

## 5  Observações

- Este brute-force só é viável porque **limitamos** o IV a strings decimais ASCII zero-padded.
- Em uso real, o IV em AES-CBC é 128 bits verdadeiramente aleatórios; brute-force é inviável.
- O script valida padding PKCS#7 e requer que o plaintext extraído seja **100 %** idêntico ao trecho conhecido (ou apenas prefixo, se `--match=prefix`), eliminando falsos-positivos.

