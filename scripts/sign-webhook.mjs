/* =========================================================
   Dev helper — sign a sample Lemon Squeezy webhook payload
   so you can test the function locally without real events.

   Usage:
     LEMONSQUEEZY_WEBHOOK_SECRET=devsecret \
       node scripts/sign-webhook.mjs subscription_created <firebase-uid> \
       > /tmp/pd-hook.json

     # then, with `netlify dev` running on :8888
     curl -sS -X POST http://localhost:8888/.netlify/functions/lemonsqueezy-webhook \
       -H "Content-Type: application/json" \
       -H "X-Signature: $(node scripts/sign-webhook.mjs subscription_created <uid> --sig-only)" \
       --data @/tmp/pd-hook.json

   Simpler: this script prints the curl command for you when run with --curl.
   ========================================================= */

import crypto from "node:crypto";

const [, , eventName = "subscription_created", uid = "TEST_UID", mode] = process.argv;
const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
if (!secret) {
  console.error("Set LEMONSQUEEZY_WEBHOOK_SECRET first.");
  process.exit(1);
}

const now = new Date();
const in7 = new Date(now.getTime() + 7 * 864e5);
const in37 = new Date(now.getTime() + 37 * 864e5);

const statusByEvent = {
  subscription_created: "on_trial",
  subscription_payment_success: "active",
  subscription_updated: "active",
  subscription_cancelled: "cancelled",
  subscription_expired: "expired",
  subscription_paused: "paused",
  subscription_resumed: "active",
  subscription_payment_failed: "past_due",
};
const status = statusByEvent[eventName] || "active";

const payload = {
  meta: { event_name: eventName, custom_data: { uid } },
  data: {
    type: "subscriptions",
    id: "999001",
    attributes: {
      store_id: 1,
      customer_id: 555001,
      product_id: 1,
      variant_id: 1,
      product_name: "Point Detective",
      variant_name: "Monthly",
      user_name: "Test Coach",
      user_email: "coach@example.com",
      status,
      status_formatted: status.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
      card_brand: "visa",
      card_last_four: "4242",
      cancelled: status === "cancelled",
      trial_ends_at: eventName === "subscription_created" ? in7.toISOString() : null,
      renews_at: in37.toISOString(),
      ends_at: status === "cancelled" ? in37.toISOString() : null,
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
      test_mode: true,
      urls: {
        update_payment_method: "https://example.lemonsqueezy.com/subscription/999001/payment-details",
        customer_portal: "https://example.lemonsqueezy.com/billing?token=demo",
      },
    },
  },
};

const body = JSON.stringify(payload);
const sig = crypto.createHmac("sha256", secret).update(body, "utf8").digest("hex");

if (mode === "--sig-only") {
  process.stdout.write(sig);
} else if (mode === "--curl") {
  const url = "http://localhost:8888/.netlify/functions/lemonsqueezy-webhook";
  console.log(
    `curl -sS -X POST ${url} \\\n` +
    `  -H "Content-Type: application/json" \\\n` +
    `  -H "X-Signature: ${sig}" \\\n` +
    `  --data '${body.replace(/'/g, "'\\''")}'`
  );
} else {
  // Default: emit the JSON body; signature goes to stderr so it doesn't pollute stdout.
  console.error(`X-Signature: ${sig}`);
  process.stdout.write(body);
}
