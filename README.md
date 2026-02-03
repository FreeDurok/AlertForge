# AlertForge

Genera infografiche per bollettini di sicurezza.

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Utilizzo

```bash
# Singolo file
python alertforge.py -i bulletins.example.json -o output.png

# Con configurazione custom
python alertforge.py -i bulletins.example.json -o output.png -c config.example.json

# Batch (più file JSON)
python alertforge.py --batch input_dir/ -od output_dir/
```

## Configurazione

Copia e modifica `config.example.json`:

| Parametro | Descrizione |
|-----------|-------------|
| `title` | Titolo header |
| `organization` | Nome organizzazione |
| `logo_path` | Path del logo (opzionale) |
| `logo_bg_replace` | Sostituisce sfondo logo (`true`/`false`) |
| `logo_bg_color` | Colore da sostituire: `black`, `white`, `#RRGGBB` o `null` |

## Formato Bollettini

```json
{
  "bulletins": [
    {
      "category": "vulnerabilita",
      "severity": "critical",
      "product": "Nome Prodotto",
      "description": "Descrizione vulnerabilità...",
      "cve_id": "CVE-2024-12345",       // opzionale
      "tags": ["RCE", "Zero-Day"],      // opzionale
      "version": "1.0",                 // opzionale
      "image": "path/to/image.png"      // opzionale
    }
  ]
}
```

| Campo | Obbligatorio | Descrizione |
|-------|:------------:|-------------|
| `category` | ✅ | `vulnerabilita`, `aggiornamenti`, `patch`, `advisory`, `incident` |
| `severity` | ✅ | `critical`, `high`, `medium`, `low`, `info` |
| `product` | ✅ | Nome del prodotto |
| `description` | ✅ | Descrizione della vulnerabilità |
| `cve_id` | ❌ | Identificativo CVE |
| `tags` | ❌ | Array di tag (max 4) |
| `version` | ❌ | Versione del prodotto |
| `image` | ❌ | Path immagine allegata |
