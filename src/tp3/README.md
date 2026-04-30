# TP3 - Captcha solver

Le TP3 correspond aux slides du cours : résoudre 5 challenges de CAPTCHA avec
`requests`, `PIL` et `pytesseract`.

## Dépendances

```bash
python -m pip install -r src/tp3/requirements.txt
sudo apt install tesseract-ocr
```

Si `tesseract` n'est pas dans le `PATH`, définir son chemin :

```bash
export TESSERACT_CMD="/usr/bin/tesseract"
```

## Lancement

```bash
python -m source.tp3.main
```

`python -m src.tp3.main` reste aussi valide.

Variables utiles :

```bash
export TP3_BASE_URL="http://31.220.95.27:9002"
export TP3_CHALLENGES=1,2,3,4,5
export TP3_RETRIES_PER_FLAG=3
export TP3_DELAY_SECONDS=0.2
```

Les valeurs connues sont appliquées automatiquement :

- challenge 1 : `1000..2000`
- challenge 2 : `2000..3000`
- challenge 3 : `3000..4000`
- challenge 4 : `7629`, avec `Magic-Word` issu du challenge 3
- challenge 5 : `8632`, avec les headers requis

Pour forcer une plage :

```bash
export TP3_FLAG_START=2000
export TP3_FLAG_END=3000
```

Pour passer en saisie manuelle :

```bash
export CAPTCHA_MODE=manual
python -m src.tp3.main
```
