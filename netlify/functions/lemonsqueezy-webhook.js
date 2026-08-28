/* =========================================================
   Point Detective — Lemon Squeezy webhook receiver
   ---------------------------------------------------------
   Verifies the X-Signature HMAC, then mirrors the current
   subscription status into Firestore at subscribers/{uid}.
   The browser app reads that doc (read-only) to decide
   whether to unlock the logger.
   ========================================================= */

const crypto = require("crypto");
const admin = require("firebase-admin");

/* ---------- Firebase Admin (init once per warm container) ---------- */
function db() {
  if (!admin.apps.length) {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new Error("FIREBASE_SERVICE_ACCOUNT is not set");
    const serviceAccount = JSON.parse(raw);
    // When the JSON is stored with escaped newlines, un-escape the private key.
    if (serviceAccount.private_key) {
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");
    }
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  }
  return admin.firestore();
}

/* ---------- Signature check ---------- */
function signatureValid(rawBody, headerSig, secret) {
  if (!headerSig || !secret) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(String(headerSig), "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ---------- Events ----------
   subscription_* events carry a SUBSCRIPTION object in data.attributes:
     status = on_trial | active | paused | past_due | unpaid | cancelled | expired
   subscription_payment_* events carry a SUBSCRIPTION-INVOICE object — a different
   shape whose status is paid | pending | void | refunded. Those must NEVER be
   written as the subscription status, so they're handled separately and only
   update payment-health fields. */
const SUBSCRIPTION_EVENTS = new Set([
  "subscription_created",
  "subscription_updated",
  "subscription_cancelled",
  "subscription_resumed",
  "subscription_paused",
  "subscription_unpaused",
  "subscription_expired",
]);
const PAYMENT_EVENTS = new Set([
  "subscription_payment_success",
  "subscription_payment_failed",
  "subscription_payment_recovered",
]);

/* ---------- Find the Firebase uid this subscription belongs to ---------- */
async function resolveUid(firestore, customData, subscriptionId, email) {
  if (customData && typeof customData.uid === "string" && customData.uid) {
    return customData.uid;
  }
  const col = firestore.collection("subscribers");

  if (subscriptionId != null) {
    const bySub = await col.where("ls_subscription_id", "==", Number(subscriptionId)).limit(1).get();
    if (!bySub.empty) return bySub.docs[0].id;
  }
  if (email) {
    const byEmail = await col.where("email", "==", email).limit(1).get();
    if (!byEmail.empty) return byEmail.docs[0].id;
  }
  return null;
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body || "", "base64").toString("utf8")
    : (event.body || "");

  const headers = event.headers || {};
  const sig = headers["x-signature"] || headers["X-Signature"];

  if (!signatureValid(rawBody, sig, process.env.LEMONSQUEEZY_WEBHOOK_SECRET)) {
    return { statusCode: 401, body: "Invalid signature" };
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (e) {
    return { statusCode: 400, body: "Bad JSON" };
  }

  const eventName = payload?.meta?.event_name;
  const customData = payload?.meta?.custom_data || {};
  const data = payload?.data || {};
  const attrs = data.attributes || {};

  const isSubEvent = SUBSCRIPTION_EVENTS.has(eventName);
  const isPayEvent = PAYMENT_EVENTS.has(eventName);

  // Acknowledge anything we don't handle so Lemon Squeezy stops retrying.
  if (!isSubEvent && !isPayEvent) {
    return { statusCode: 200, body: `Ignored event: ${eventName || "unknown"}` };
  }

  let firestore;
  try {
    firestore = db();
  } catch (e) {
    console.error("Firebase init failed:", e.message);
    return { statusCode: 500, body: "Server not configured" };
  }

  // For subscription_* events the subscription id is data.id.
  // For payment events data.id is the *invoice* id; the subscription id is in attrs.
  const subscriptionId = isSubEvent
    ? (data.id != null ? Number(data.id) : null)
    : (attrs.subscription_id != null ? Number(attrs.subscription_id) : null);
  const email = attrs.user_email || null;

  const uid = await resolveUid(firestore, customData, subscriptionId, email);
  if (!uid) {
    console.warn(
      `No uid for ${eventName} (subscription ${subscriptionId}, email ${email}). ` +
      `custom_data=${JSON.stringify(customData)}`
    );
    // 200 on purpose: retrying won't help until the checkout carries a uid.
    return { statusCode: 200, body: "No matching user" };
  }

  let record;
  if (isSubEvent) {
    const urls = attrs.urls || {};
    record = {
      email,
      status: attrs.status || "unpaid",
      status_formatted: attrs.status_formatted || null,
      renews_at: attrs.renews_at || null,
      ends_at: attrs.ends_at || null,
      trial_ends_at: attrs.trial_ends_at || null,
      ls_subscription_id: subscriptionId,
      ls_customer_id: attrs.customer_id != null ? Number(attrs.customer_id) : null,
      ls_variant_id: attrs.variant_id != null ? Number(attrs.variant_id) : null,
      ls_product_name: attrs.product_name || null,
      ls_variant_name: attrs.variant_name || null,
      card_brand: attrs.card_brand || null,
      card_last_four: attrs.card_last_four || null,
      test_mode: attrs.test_mode === true,
      customer_portal_url: urls.customer_portal || null,
      update_payment_method_url: urls.update_payment_method || null,
      last_event: eventName,
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    };
  } else {
    // Payment/invoice event — touch ONLY payment-health fields, never `status`.
    record = {
      card_brand: attrs.card_brand || null,
      card_last_four: attrs.card_last_four || null,
      last_payment_event: eventName,
      last_payment_status: attrs.status || null, // paid | pending | void | refunded
      last_payment_at: admin.firestore.FieldValue.serverTimestamp(),
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    };
  }

  try {
    await firestore.collection("subscribers").doc(uid).set(record, { merge: true });
  } catch (e) {
    console.error("Firestore write failed:", e.message);
    return { statusCode: 500, body: "Write failed" };
  }

  const outcome = isSubEvent ? record.status : record.last_payment_status;
  return { statusCode: 200, body: `OK (${eventName} -> ${outcome} for ${uid})` };
};
