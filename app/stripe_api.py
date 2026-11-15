"""CatalogIQ — Stripe via raw HTTPS (stdlib only, no SDK).

Checkout Sessions + Customer Portal sessions are created server-side so a
payment is BOUND to an account + pending order (the Tier-1 cure). Webhook
signatures are verified with HMAC-SHA256 over the raw payload.

STRIPE_SECRET_KEY absent (local dev) => stub mode: checkout returns a local
stub URL and the test harness drives the webhook handler directly.
"""
import os, json, hmac, hashlib, time, urllib.request, urllib.parse

KEY = os.environ.get("STRIPE_SECRET_KEY", "")
WHSEC = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
API = "https://api.stripe.com/v1"

PRICES = {  # live ids on the shared Apex Stripe account; env overrides let a
    # test-mode deployment bind test-mode prices without a code change.
    "starter": os.environ.get("STRIPE_PRICE_STARTER", "price_1UXXlbEYdf2rIbh9oByF0xGG"),
    "growth": os.environ.get("STRIPE_PRICE_GROWTH", "price_1UXXm1EYdf2rIbh9OPBABjgX"),
    "scale": os.environ.get("STRIPE_PRICE_SCALE", "price_1UXXmbEYdf2rIbh9etGNGvCe"),
    "translate": os.environ.get("STRIPE_PRICE_TRANSLATE", "price_1UXXnZEYdf2rIbh9KFPetEvJ"),
}
PLANS = {
    "starter": {"name": "Starter", "price": "$99/mo", "sku_cap": 500},
    "growth": {"name": "Growth", "price": "$199/mo", "sku_cap": 2500},
    "scale": {"name": "Scale", "price": "$399/mo", "sku_cap": 10000},
}

stub_mode = not KEY
# The stub checkout may only operate when explicitly enabled (local harness).
# A deployed instance without a key must never fabricate a payment surface.
ALLOW_STUB = os.environ.get("CIQ_ALLOW_STUB") == "1"


def _call(path, params):
    data = urllib.parse.urlencode(params, doseq=True).encode()
    req = urllib.request.Request(API + path, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {KEY}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


LINKS = {  # Route F: Stripe Payment Links on the Apex account (live ids);
    # env overrides bind test-mode links for the L4 battery.
    "starter": os.environ.get("STRIPE_LINK_STARTER", "https://buy.stripe.com/fZu14n3yXcvyajagBkaR20f"),
    "growth": os.environ.get("STRIPE_LINK_GROWTH", "https://buy.stripe.com/6oU4gzedB0MQ0IA84OaR20g"),
    "scale": os.environ.get("STRIPE_LINK_SCALE", "https://buy.stripe.com/14A9AT6L9bru8b2bh0aR20h"),
    "translate": os.environ.get("STRIPE_LINK_TRANSLATE", "https://buy.stripe.com/5kQ7sL9Xl2UYezqdp8aR20i"),
}


def create_checkout(base_url, workspace_ref, order_ref, plan, email):
    """Return (checkout_url, session_id). Plan must be a key of PRICES.

    Route F (no secret key): the buyer pays on the plan's Stripe Payment
    Link bound to this workspace via client_reference_id; the webhook
    reconciles the pending order. With a key (Route E, live gate), a real
    Checkout Session is created instead."""
    if stub_mode:
        if ALLOW_STUB:
            return (f"{base_url}/stub-checkout?order={order_ref}&plan={plan}",
                    f"cs_stub_{order_ref}")
        link = LINKS.get(plan)
        if link:
            return (f"{link}?client_reference_id={workspace_ref}",
                    f"link_{order_ref}")
        return (f"{base_url}/app/billing?pay=configuring",
                f"cs_unconfigured_{order_ref}")
    params = {
        "mode": "subscription",
        "line_items[0][price]": PRICES[plan],
        "line_items[0][quantity]": 1,
        "customer_email": email,
        "client_reference_id": workspace_ref,
        "metadata[workspace_ref]": workspace_ref,
        "metadata[order_ref]": order_ref,
        "metadata[company]": "CatalogIQ",
        "subscription_data[metadata][workspace_ref]": workspace_ref,
        "subscription_data[metadata][order_ref]": order_ref,
        "success_url": f"{base_url}/billing/return?order={order_ref}",
        "cancel_url": f"{base_url}/app?checkout=cancelled",
    }
    s = _call("/checkout/sessions", params)
    return s["url"], s["id"]


def create_portal(base_url, customer_id):
    if stub_mode or not customer_id:
        return f"{base_url}/app/billing"
    s = _call("/billing_portal/sessions",
              {"customer": customer_id, "return_url": f"{base_url}/app/billing"})
    return s["url"]


def verify_webhook(payload: bytes, sig_header: str, secret: str = None,
                   tolerance: int = 300) -> bool:
    secret = secret if secret is not None else WHSEC
    if not secret:
        return stub_mode  # local harness only; prod requires the secret
    try:
        parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
        ts = int(parts["t"])
        if abs(time.time() - ts) > tolerance:
            return False
        signed = f"{ts}.".encode() + payload
        expect = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expect, parts.get("v1", ""))
    except Exception:
        return False
