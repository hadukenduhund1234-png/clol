# Listify 📋

Anmeldelisten-App für Railway. Erstelle Listen mit Datum, Beschreibung und Slot-Anzahl — Nutzer tragen sich per Nickname ein.

## Lokaler Start

```bash
npm install
npm start
# → http://localhost:3000
```

## Railway Deployment

### Option A — GitHub (empfohlen)
1. Ordner als GitHub-Repo pushen
2. [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub Repo**
3. Repo wählen → fertig ✓

### Option B — CLI
```bash
npm i -g @railway/cli
railway login
railway init
railway up
```

## Persistente Daten (wichtig!)

Die SQLite-DB liegt in `/data/app.db`. Damit sie Railway-Restarts überlebt:

1. Railway Dashboard → Service → **Volumes** → **Add Volume**
2. Mount Path: `/app/data`
3. Umgebungsvariable setzen: `DATA_DIR=/app/data`

## Env-Variablen

| Variable | Default | Beschreibung |
|----------|---------|--------------|
| `PORT` | `3000` | Wird von Railway automatisch gesetzt |
| `DATA_DIR` | `./data` | Pfad zur SQLite-Datenbankdatei |
