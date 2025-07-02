# use venv

python -m venv venv 

# ativar o venv depois

pip install tqdm pycryptodomex re

# rodar com 

bruteforce_iv.py SKYWALKER1980 "Star Wars: Episode" 2c70e097ae1d4779068749584f1ec1a165fa8ce7c58fa02a9da9006dab69a0cb --digits=9
bruteforce_iv.py TEST1 "EL" b5ffb348cb01ef862ea8df39e5b21206 --digits=9 # esse roda com --digits=2 também
