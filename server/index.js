
import express from "express";
import nacl from "tweetnacl";
import bs58 from "bs58";
import crypto from "crypto";
import cors from "cors";

const app = express();
app.use(express.json());

// ==== Config (tune as needed) ====
const PORT = process.env.PORT || 4700;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;   // challenge validity
const CLOCK_SKEW_MS    = 2 * 60 * 1000;   // allowed clock skew in timestamp
const NONCE_BYTES = 16;

// In-memory nonce store (nonce -> expiresAt). For MVP only.
const nonces = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [n, exp] of nonces.entries()) if (exp < now) nonces.delete(n);
}, 30_000);

// Utilities
const nowMs = () => Date.now();
const b64url = (buf) =>
  Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const parseB64urlJson = (s) => JSON.parse(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
const makeNonce = () => b64url(crypto.randomBytes(NONCE_BYTES));
const buildMessage = ({ timestamp, url, nonce }) => `${timestamp}|${url}|${nonce}`;

// Issue a fresh challenge (status 470)
function sendProofChallenge(req, res) {
  const nonce = makeNonce();
  const issuedAt = nowMs();
  const expiresAt = issuedAt + CHALLENGE_TTL_MS;

  nonces.set(nonce, expiresAt);

  const resource = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  const challenge = {
    version: "x470.v1",
    method: "solana-ed25519",
    algo: "ed25519",
    resource,
    issued_at: issuedAt,
    expires_at: expiresAt,
    nonce,
    // Clients must sign: `${timestamp}|${resource}|${nonce}`
    message_format: "timestamp|url|nonce",
    header: "Proof-Of-Human",
  };

  // You can also advertise the method via a header if you like:
  res.setHeader("Proof-Of-Human-Method", "solana-ed25519; header=Proof-Of-Human; format=timestamp|url|nonce");

  return res
    .status(470) // <— custom status code for "Proof-of-Human Required"
    .json(challenge);
}

// Middleware to verify Proof-Of-Human header for protected routes
async function requireHuman(req, res, next) {
  const pohHeader = req.get("Proof-Of-Human");
  if (!pohHeader) return sendProofChallenge(req, res);

  // Expect: "v1 <base64url(json)>"
  const [scheme, token] = pohHeader.split(/\s+/, 2);
  if (!scheme || !token || scheme.toLowerCase() !== "v1") return sendProofChallenge(req, res);

  let payload;
  try {
    payload = parseB64urlJson(token);
    // payload = { pubkey, signature, timestamp, nonce }
  } catch {
    return sendProofChallenge(req, res);
  }

  const { pubkey, signature, timestamp, nonce } = payload || {};
  
  if (!pubkey || !signature || !timestamp || !nonce) return sendProofChallenge(req, res);

  // Basic time checks
  const ts = Number(timestamp);
  const now = nowMs();
  if (!Number.isFinite(ts)) return sendProofChallenge(req, res);
  if (Math.abs(now - ts) > (CHALLENGE_TTL_MS + CLOCK_SKEW_MS)) return sendProofChallenge(req, res);
  // Nonce must be active and unused
  const exp = nonces.get(nonce);
  if (!exp || exp < now) return sendProofChallenge(req, res);
  
  
  // Re-construct the expected message and verify ed25519 signature
  const resource = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  const msg = buildMessage({ timestamp: ts, url: resource, nonce });
  const message = new TextEncoder().encode(msg);

  let ok = false;
  try {
    const pk = bs58.decode(pubkey);       // 32 bytes
    const sig = bs58.decode(signature);   // 64 bytes

    if (pk.length === 32 && sig.length === 64) {
      ok = nacl.sign.detached.verify(message, sig, pk);
    }
  } catch(e) {
    ok = false;
  }
  if (!ok) return sendProofChallenge(req, res);

  // Mark nonce as used (prevent replay)
  nonces.delete(nonce);

  // Attach identity info for your app logic
  req.proofOfHuman = { pubkey, timestamp: ts, nonce, method: "solana-ed25519" };
  next();
}

app.use(cors({
  origin: true, // reflect the request origin (or use ["http://localhost:5173", ...])
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Proof-Of-Human"],
  credentials: false
}));

// Public ping
app.get("/", (_req, res) => {
  res.type("text/plain").send("x470 Proof-of-Human demo. Try GET /secret");
});

// Protected resource example
app.get("/secret", requireHuman, (req, res) => {
  res.json({
    message: "🎉 Human verified. Here is the protected data.",
    you_are: req.proofOfHuman,
    data: { answer: 42, note: "This payload is only visible after x470 proof." },
  });
});

app.listen(PORT, () => {
  console.log(`x470 server listening on http://localhost:${PORT}`);
  console.log("Try: curl -i http://localhost:%s/secret", PORT);
});