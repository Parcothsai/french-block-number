
# ☎️ API de Soumission de Numéros Bloqués

Ce projet fournit une API sécurisée permettant aux utilisateurs de soumettre une liste de numéros de téléphone à bloquer. Il utilise des clés API, des signatures RSA, une base de données SQLite, et propose une authentification admin séparée.

---

## ⚙️ Fonctionnalités principales

- 📥 Envoi de fichiers `.txt` contenant des numéros à bloquer
- 🔒 Authentification via API key et signature RSA
- 📊 Statistiques (avec cache)
- 🛡️ Authentification Admin (via `.env_admin`)
- 📦 API RESTful avec Express.js
- 🐳 Déploiement avec Docker

---

## 🏁 Démarrage rapide

### Prérequis

- Node.js 18+
- Docker & Docker Compose
- OpenSSL (pour générer les clés RSA)

### 1. Cloner le repo

```bash
git clone <repository_url>
cd <repository_directory>
```

### 2. Variables d'environnement

Créez un fichier `.env_admin` à la racine :

```ini
ADMIN_USER=admin
ADMIN_PASSWORD=motdepasseultrasecret
```

### 3. Générer une paire de clés (pour un utilisateur)

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -outform PEM -out public.pem
```

Envoyer la clé publique via l’endpoint `/upload-public-key`.

---

## 📦 Docker

### Utilisation avec Docker Compose

#### 1. Construire et lancer

```bash
docker-compose up --build
```

#### 2. Accès

```txt
http://localhost:3000
```

### Dockerfile

L’image installe les dépendances et expose le port 3000.

---

## 📮 Endpoints

### 🔐 Authentification & Clés

#### `POST /register`

Enregistre ou connecte un utilisateur via une API key signée.

```json
{
  "apiKey": "votre_cle",
  "signature": "signature_base64"
}
```

#### `POST /upload-public-key`

```json
{
  "apiKey": "votre_cle",
  "publicKey": "clé_publique_sans_retours_ligne"
}
```

---

### 📥 Soumission de numéros

#### `POST /submit-blocked-numbers`

Headers requis :

- `apikey`
- `userid`
- `signature`
- `timestamp`

Fichier `.txt` envoyé via champ `file`.

---

### 📊 Statistiques

#### `GET /stats`

Retourne les statistiques générales. Utilise un cache TTL de 5 minutes.

---

### 🧹 Admin

#### `GET /admin/invalidate-cache`

Protégé par **authentification HTTP Basic** :

```http
Authorization: Basic base64(admin:motdepasse)
```

---

### 🩺 Santé du service

#### `GET /health`

Permet de vérifier si le serveur est en ligne.

---

## 🧪 Tests

Testez via Postman ou curl :

```bash
curl -X POST http://localhost:3000/register   -H "Content-Type: application/json"   -d '{"apiKey":"clé","signature":"signature"}'
```

---

## 🗃️ Structure SQLite

- `ApiKeys`: gère les utilisateurs & clés
- `UserSubmissions`: 1 soumission par jour max
- `PhoneNumberEntries`: enregistre les numéros
- `BlockedNumbersCount`: nombre d’occurrences par numéro

---

## 🔒 Sécurité

- Chaque requête est signée via RSA (clé publique/privée)
- Les fichiers `.txt` sont filtrés et limités à 1 Mo
- Le serveur ne stocke que les clés publiques

---

## 📁 Arborescence

```bash
├── uploads/
├── public_keys/
├── blockedNumbers.db
├── server.js
├── dockerfile
├── compose.yml
├── .env_admin
└── README.md
```

---

## 📜 Licence

MIT - Projet à usage pédagogique ou communautaire.
