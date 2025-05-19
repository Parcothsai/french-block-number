const express = require("express");
const multer = require("multer");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
require("dotenv").config({ path: ".env_admin" });
const app = express();
const port = 3000;

// 🔧 Helper de réponse uniforme
const jsonResponse = (res, statusCode, success, message, data = null) => {
  res.status(statusCode).json({ success, message, ...(data ? { data } : {}) });
};

console.log("🚀 Serveur démarré sur http://localhost:" + port + " [debut=true]");

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");
if (!fs.existsSync("public_keys")) fs.mkdirSync("public_keys");

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, "uploads/"),
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
  }),
  fileFilter: (req, file, cb) => {
    console.log("🧾 Vérification du type MIME du fichier [debut=true]");
    if (file.mimetype === "text/plain") cb(null, true);
    else cb(new Error("Seuls les fichiers texte sont autorisés !"), false);
  },
  limits: { fileSize: 1024 * 1024 },
});

app.use(bodyParser.json());

const db = new sqlite3.Database("./blockedNumbers.db");
db.serialize(() => {
  console.log("📦 Initialisation de la base de données [debut=true]");
  db.run(`CREATE TABLE IF NOT EXISTS ApiKeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT,
    user_id TEXT UNIQUE,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS UserSubmissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE,
    last_submission DATE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS PhoneNumberEntries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    phone_number TEXT,
    entry_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, phone_number)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS BlockedNumbersCount (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone_number TEXT UNIQUE,
    count INTEGER DEFAULT 1,
    last_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
});

app.post("/register", (req, res) => {
  console.log("📩 Reçu /register [debut=true]");
  const { apiKey, signature } = req.body;
  console.log(apiKey, signature)
  if (!apiKey || !signature)
    return jsonResponse(res, 400, false, "Clé API ou signature manquante");

  const pubKeyPath = path.join(__dirname, "public_keys", `${apiKey}.pem`);
  console.log(pubKeyPath);
  if (!fs.existsSync(pubKeyPath)) {
    console.warn(`❌ Clé publique absente pour ${apiKey} [debut=true]`);
    return jsonResponse(res, 401, false, "Clé publique non trouvée");
  }

  const publicKey = fs.readFileSync(pubKeyPath, "utf8");
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(apiKey);
  const isValid = verifier.verify(publicKey, signature, "base64");

  if (!isValid) {
    console.warn("❌ Signature invalide [debut=true]");
    return jsonResponse(res, 401, false, "Signature invalide");
  }

  db.get(`SELECT user_id FROM ApiKeys WHERE key = ?`, [apiKey], (err, row) => {
    if (err) {
      console.error("❌ Erreur DB check API key [debut=true]");
      return jsonResponse(res, 500, false, "Erreur DB");
    }
    if (row) {
      console.log(`🔁 Clé API existante → userId = ${row.user_id} [debut=true]`);
      return jsonResponse(res, 200, true, "Connexion OK", { userId: row.user_id });
    }

    const userId = uuidv4();
    db.run(`INSERT INTO ApiKeys (key, user_id) VALUES (?, ?)`, [apiKey, userId], (err) => {
      if (err) return jsonResponse(res, 500, false, "Erreur insertion API key");
      db.run(`INSERT INTO UserSubmissions(user_id) VALUES(?)`, [userId], (err2) => {
        if (err2) return jsonResponse(res, 500, false, "Erreur insertion UserSubmissions");
        console.log(`✅ Nouvelle clé enregistrée : ${userId} [debut=true]`);
        jsonResponse(res, 200, true, "Inscription réussie", { userId });
      });
    });
  });
});

app.post("/upload-public-key", (req, res) => {
  console.log("📨 Reçu /upload-public-key [debut=true]");
  const { apiKey, publicKey } = req.body;
  if (!apiKey || !publicKey)
    return jsonResponse(res, 400, false, "apiKey ou clé publique manquante");

  const cleanKey = publicKey.replace(/\r?\n|\r/g, '');
  const pem = `-----BEGIN PUBLIC KEY-----\n${cleanKey}\n-----END PUBLIC KEY-----\n`;
  const filePath = path.join(__dirname, "public_keys", `${apiKey}.pem`);

  fs.writeFile(filePath, pem, (err) => {
    if (err) {
      console.error("❌ Erreur écriture clé publique [debut=true]", err);
      return jsonResponse(res, 500, false, "Erreur serveur");
    }
    console.log(`✅ Clé publique enregistrée : ${filePath} [debut=true]`);
    jsonResponse(res, 200, true, "Clé publique enregistrée");
  });
});

const checkDailySubmissionLimit = (userId, callback) => {
  const today = new Date().toISOString().split("T")[0];
  db.get(`SELECT last_submission FROM UserSubmissions WHERE user_id = ?`, [userId], (err, row) => {
    if (err) return callback(err);
    if (row && row.last_submission === today) return callback(null, false);
    return callback(null, true);
  });
};

const authenticateSubmission = (req, res, next) => {
  console.log("🔐 Authentification requise [debut=true]");
  const { apikey, signature, timestamp, userid } = req.headers;
  if (!apikey || !signature || !timestamp || !userid)
    return jsonResponse(res, 401, false, "En-têtes manquants");

  const pubKeyPath = path.join(__dirname, "public_keys", `${apikey}.pem`);
  if (!fs.existsSync(pubKeyPath)) {
    console.warn("❌ Clé publique manquante pour cette requête [debut=true]");
    return jsonResponse(res, 401, false, "Clé publique non trouvée");
  }

  const publicKey = fs.readFileSync(pubKeyPath, "utf8");
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(apikey + userid + timestamp);
  const isValid = verifier.verify(publicKey, signature, "base64");

  if (!isValid) {
    console.warn("❌ Signature invalide [debut=true]");
    return jsonResponse(res, 401, false, "Signature invalide");
  }

  db.get(`SELECT * FROM ApiKeys WHERE key = ? AND status = 'active'`, [apikey], (err, apiRow) => {
    if (err || !apiRow) return jsonResponse(res, 401, false, "Clé API invalide ou inactive");

    db.get(`SELECT * FROM UserSubmissions WHERE user_id = ?`, [userid], (err2, userRow) => {
      if (err2 || !userRow) return jsonResponse(res, 401, false, "UserId non reconnu");
      req.userId = userid;
      console.log(`✅ Utilisateur authentifié : ${userid} [debut=true]`);
      next();
    });
  });
};

app.post('/submit-blocked-numbers', authenticateSubmission, (req, res) => {
  const userId = req.userId;
  console.log(`📥 Reçu /submit-blocked-numbers pour ${userId} [debut=true]`);

  checkDailySubmissionLimit(userId, (errLimit, allowed) => {
    if (errLimit) {
      console.error("❌ Erreur vérification quota [debut=true]");
      return jsonResponse(res, 500, false, "Erreur vérification quota");
    }
    if (!allowed) {
      console.warn(`🚫 Limite quotidienne atteinte pour ${userId} [debut=true]`);
      return jsonResponse(res, 200, false, "Limite quotidienne atteinte. Disponible demain :)");
    }

    upload.single('file')(req, res, (err) => {
      if (err || !req.file) {
        console.warn('❌ Fichier manquant ou invalide [debut=true]');
        return jsonResponse(res, 400, false, err ? err.message : 'Fichier manquant');
      }

      console.log(`📄 Fichier reçu : ${req.file.originalname} [debut=true]`);

      fs.readFile(req.file.path, 'utf8', (err, data) => {
        if (err) return jsonResponse(res, 500, false, 'Erreur lecture fichier');

        const allLines = data.split('\n').map(line => line.trim()).filter(Boolean);
        if (allLines.length === 0) return jsonResponse(res, 400, false, 'Fichier vide');

        const phoneNumbers = [...new Set(allLines)];
        console.log(`☎️ ${phoneNumbers.length} numéros uniques extraits. [debut=true]`);

        const placeholders = phoneNumbers.map(() => '?').join(',');
        db.all(`SELECT phone_number FROM PhoneNumberEntries WHERE user_id = ? AND phone_number IN (${placeholders})`, [userId, ...phoneNumbers], (err2, rows) => {
          if (err2) return jsonResponse(res, 500, false, 'Erreur base de données');

          const alreadySent = new Set((rows || []).map(r => r.phone_number));
          const MAX_DAILY = 100;
          const toInsert = phoneNumbers.filter(pn => !alreadySent.has(pn)).slice(0, MAX_DAILY);

          // Si aucun nouveau numéro accepté
          if (toInsert.length === 0) {
            console.log('ℹ️ Aucun nouveau numéro à enregistrer [debut=true]');
            return jsonResponse(res, 200, true, 'Aucun nouveau numéro. Aucune action effectuée.', { acceptedNumbers: [] });
          }

          const stmt1 = db.prepare(`INSERT INTO PhoneNumberEntries(user_id, phone_number) VALUES(?, ?)`);
          const stmt2 = db.prepare(`
            INSERT INTO BlockedNumbersCount(phone_number, count, last_added)
            VALUES(?, 1, CURRENT_TIMESTAMP)
            ON CONFLICT(phone_number)
            DO UPDATE SET count = count + 1, last_added = CURRENT_TIMESTAMP
          `);

          const acceptedNumbers = [];

          const insertPromises = toInsert.map(pn => new Promise(resolve => {
            stmt1.run(userId, pn, (errInsert) => {
              if (errInsert) {
                console.warn(`⚠️ Doublon ignoré pour ${pn}`);
              } else {
                acceptedNumbers.push(pn);
              }
              stmt2.run(pn, () => resolve());
            });
          }));

          Promise.all(insertPromises).then(() => {
            stmt1.finalize();
            stmt2.finalize();

            db.run(`UPDATE UserSubmissions SET last_submission = DATE('now') WHERE user_id = ?`, [userId], (err3) => {
              if (err3) return jsonResponse(res, 500, false, 'Erreur MAJ date');

              console.log(`✅ ${acceptedNumbers.length} numéro(s) enregistrés avec succès [debut=true]`);
              jsonResponse(res, 200, true, `${acceptedNumbers.length} numéro(s) enregistrés avec succès. MERCI !`, {
                acceptedNumbers,
              });
            });
          });
        });
      });
    });
  });
});

const { promisify } = require("util");

const cacheStats = {
  data: null,
  lastUpdated: 0,
  ttl: 300 * 1000 // 300 secondes
};

// app.get("/stats", authenticateSubmission, async (req, res) => {
app.get("/stats", async (req, res) => {
  console.log("📊 Reçu /stats [debut=true]");

  const now = Date.now();
  if (cacheStats.data && now - cacheStats.lastUpdated < cacheStats.ttl) {
    console.log("⚡️ Cache stats utilisé");
    return jsonResponse(res, 200, true, "Statistiques récupérées (cache)", cacheStats.data);
  }

  const getAsync = promisify(db.get.bind(db));
  const allAsync = promisify(db.all.bind(db));

  const stats = {};

  try {
    const totalUsersRow = await getAsync(`SELECT COUNT(*) AS total_users FROM ApiKeys`);
    stats.totalUsers = totalUsersRow.total_users;

    const totalBlockedRow = await getAsync(`SELECT COUNT(*) AS total_blocked_entries FROM PhoneNumberEntries`);
    stats.totalBlockedEntries = totalBlockedRow.total_blocked_entries;

    const uniqueBlockedRow = await getAsync(`SELECT COUNT(*) AS total_unique_blocked_numbers FROM BlockedNumbersCount`);
    stats.totalUniqueBlockedNumbers = uniqueBlockedRow.total_unique_blocked_numbers;

    const topNumbers = await allAsync(`
      SELECT phone_number, count 
      FROM BlockedNumbersCount 
      ORDER BY count DESC 
      LIMIT 5
    `);
    stats.topBlockedNumbers = topNumbers;

    const avgRow = await getAsync(`
      SELECT COUNT(*) * 1.0 / (SELECT COUNT(*) FROM ApiKeys) AS avg_submissions_per_user
      FROM PhoneNumberEntries
    `);
    stats.averageSubmissionsPerUser = parseFloat((avgRow?.avg_submissions_per_user || 0).toFixed(2));

    // Cache les données
    const retrievedAt = getParisTimestamp();
    stats.retrievedAt = retrievedAt;
    cacheStats.data = stats;
    cacheStats.lastUpdated = Date.now();

    jsonResponse(res, 200, true, "Statistiques récupérées", {
      ...stats,
      retrievedAt: getParisTimestamp()
    });
  } catch (err) {
    console.error("❌ Erreur récupération stats :", err);
    jsonResponse(res, 500, false, "Erreur lors de la récupération des statistiques");
  }
});

// Fonction pour obtenir l'heure de Paris au format ISO
function getParisTimestamp() {
  const date = new Date();
  const formatter = new Intl.DateTimeFormat('fr-FR', {
    timeZone: 'Europe/Paris',
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
  const parts = formatter.formatToParts(date);
  const get = (type) => parts.find(p => p.type === type)?.value;
  return `${get('day')}/${get('month')}/${get('year')} à ${get('hour')}:${get('minute')}`;
}


const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Admin Area"');
    return res.status(401).send("Authentification requise");
  }

  const base64Credentials = authHeader.split(" ")[1];
  const credentials = Buffer.from(base64Credentials, "base64").toString("ascii");
  const [username, password] = credentials.split(":");

  const validUser = process.env.ADMIN_USER;
  const validPass = process.env.ADMIN_PASSWORD;

  if (username === validUser && password === validPass) {
    return next();
  }

  res.status(403).send("Accès interdit");
};

app.get("/admin/invalidate-cache", authenticateAdmin, (req, res) => {
  cacheStats.data = null;
  cacheStats.lastUpdated = 0;
  res.send("🧹 Cache stats invalidé");
});

// Route de vérification (JSON)
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'Le serveur fonctionne 🚀',
    timestamp: getParisTimestamp()
  });
});

app.listen(port);
