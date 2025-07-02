# Brute‑Force IV (AES‑CBC)

Este repositório contém um script (`mini_bruteforce.py`) que demonstra um ataque por força‑bruta ao vetor de inicialização (IV) em AES‑CBC **quando** o espaço de busca do IV é reduzido a strings numéricas ASCII zero‑padded.

---

## 1  Preparação do ambiente Python

```bash
# criar e ativar ambiente virtual
python -m venv venv
.\venv\Scripts\activate      # Windows PowerShell / cmd
# pip install – somente três dependências
pip install tqdm pycryptodomex
```

> O módulo `pycryptodomex` é preferido para evitar conflito de namespace com instalações pré‑existentes do `Crypto`.

---

## 2  Uso rápido

```bash
python mini_bruteforce.py SKYWALKER1980 "Star Wars: Episode" \
  2c70e097ae1d4779068749584f1ec1a165fa8ce7c58fa02a9da9006dab69a0cb \
  --digits=9
```

Para o vetor de teste mínimo:

```bash
python mini_bruteforce.py TEST1 "EL" b5ffb348cb01ef862ea8df39e5b21206 --digits=2
```

---

## 3  Vetores de teste escalonados

Cada linha abaixo é independente — copie e cole no terminal.  O parâmetro `--start-index` faz a execução começar poucos milhares antes do IV correto, reduzindo o tempo de demonstração.

### 3.1  IVs de 1 até 6 dígitos

```text
.\venv\Scripts\python.exe mini_bruteforce.py SEED5          "PLAINTEXT_5"          3887850d67ac20b0818a0c8aba30b502                                                    --digits=1
.\venv\Scripts\python.exe mini_bruteforce.py SEED50        "PLAINTEXT_50"         cc6c6205a9183313a201be5f15e64ac9                                                     --digits=2 --start-index=45
.\venv\Scripts\python.exe mini_bruteforce.py SEED500       "PLAINTEXT_500"        f31c4ce996ac3415d9a07397f34112f7                                                     --digits=3 --start-index=490
.\venv\Scripts\python.exe mini_bruteforce.py SEED5000      "PLAINTEXT_5000"       43e714cca0012d943df66b56e950b898                                                    --digits=4 --start-index=4980
.\venv\Scripts\python.exe mini_bruteforce.py SEED50000     "PLAINTEXT_50000"      85021974ddfe491c59a2bcf1fcfad335                                                    --digits=5 --start-index=49800
.\venv\Scripts\python.exe mini_bruteforce.py SEED500000    "PLAINTEXT_500000"     a4bef1d9545c0404f8570c6790e48a8f40d6af9e96d3f5e905eed658ff59532a                  --digits=6 --start-index=495000
```

### 3.2  IVs de 7 até 9 dígitos

```text
.\venv\Scripts\python.exe mini_bruteforce.py SEED5000000   "PLAINTEXT_5000000"    fbca04103f4c35a28c174ff2e2e77736e4470cc265c65edae2b625174550099a                --digits=7 --start-index=4900000
.\venv\Scripts\python.exe mini_bruteforce.py SEED50000000  "PLAINTEXT_50000000"   0f14ce31985982bf2ce282455845a694094a86e5cf9bb483ac25bd4095883d29               --digits=8 --start-index=49000000
.\venv\Scripts\python.exe mini_bruteforce.py SEED500000000 "PLAINTEXT_500000000"  9ce9be61f729e0eeb21502c7368a902426191239f73d9e61529b3a7cbe5a4c65              --digits=9 --start-index=495000000
```

Cada execução exibe um **Execution ID (UUID)**, útil para acompanhar múltiplas instâncias em paralelo.  O checkpoint gerado também usa esse UUID, evitando colisão quando você distribui o trabalho em vários terminais ou máquinas.

---

## 4  Dividindo o trabalho em "fatias"

Para atacar um espaço grande (ex.: `--digits=9`) em paralelo:

- **Fatias de 10 milhões** — rode a mesma linha mudando `--start-index` para `0`, `10_000_000`, `20_000_000`, … em terminais diferentes.
- O script parará automaticamente quando encontrar o IV ou quando o intervalo terminar.

---

## 5  Observações

- Este brute‑force só é viável porque **limitamos** o IV a números decimais ASCII.
- Em uso real, o IV em AES‑CBC tem 128 bits aleatórios; brute‑force é matematicamente inviável.
- O script valida padding PKCS#7 e exige que o plaintext extraído seja **100 %** idêntico ao texto conhecido, eliminando falsos‑positivos.

