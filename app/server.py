"""CatalogIQ customer app — accounts, workspaces, catalog upload, FACT LOCK
drafts, review/approve/export, and account-bound Stripe billing.

Stdlib-only (built 2026-11-15 under the egress constraint: pip is unreachable
from the build shell; the deployed host installs nothing either — this file
runs on bare Python 3.12).

Tier-1 cure construction (Director order 2026-11-15; ChatGPT consult
APPROVED WITH REQUIRED EDITS, record CONSULT-2026-11-15-TIER1-CURE.md):
payment creates a durable order + entitlement; upload produces reviewable
drafts; subscription lifecycle is reconciled from verified webhooks.
"""
import os, re, json, html, secrets, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from db import DB
import auth as A
import catalog as C
import stripe_api as S
import mailer as M

BASE = os.environ.get("BASE_URL", "http://localhost:8077").rstrip("/")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
EXPORT_DIR = os.path.join(os.path.dirname(__file__), "exports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)
MAX_UPLOAD = 10 * 1024 * 1024  # 10 MB published limit

db = DB()
db.init_schema()

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def esc(x):
    return html.escape(str(x if x is not None else ""), quote=True)

def ref_for(seq, prefix="CIQ"):
    import datetime
    return f"{prefix}-{datetime.datetime.now().year}-{seq:05d}"

_rate = {}
def rate_ok(key, limit=12, window=600):
    import time
    now = time.time()
    hits = [t for t in _rate.get(key, []) if now - t < window]
    _rate[key] = hits + [now]
    return len(hits) < limit

def get_user(handler):
    cookie = handler.headers.get("Cookie", "")
    m = re.search(r"ciq_session=([A-Za-z0-9_\-]+)", cookie or "")
    if not m:
        return None, None
    row = db.one("SELECT u.*, s.expires_at AS session_expires_at FROM sessions s "
                 "JOIN users u ON u.id=s.user_id WHERE s.token_hash=%s",
                 (A.tok_hash(m.group(1)),))
    if not row or A.is_expired(row.get("session_expires_at", "")):
        return None, None
    return row, m.group(1)

def workspace_of(user):
    return db.one("SELECT * FROM workspaces WHERE user_id=%s", (user["id"],))

def csrf_of(raw_token):
    return A.tok_hash("csrf:" + raw_token)[:32]

def check_csrf(handler, form):
    _, raw = get_user(handler)
    if not raw:
        return False
    return form.get("csrf", [""])[0] == csrf_of(raw)

# --------------------------------------------------------------------------
# layout
# --------------------------------------------------------------------------
def page(title, body, user=None, raw_token=None):
    nav = ""
    if user:
        nav = ('<nav><a href="/app">Workspace</a><a href="/app/upload">Upload catalog</a>'
               '<a href="/app/drafts">Drafts</a><a href="/app/billing">Billing</a>'
               '<form method="post" action="/logout" style="display:inline">'
               f'<input type="hidden" name="csrf" value="{csrf_of(raw_token)}">'
               '<button class="linkbtn" type="submit">Sign out</button></form></nav>')
    else:
        nav = ('<nav><a href="/login">Sign in</a>'
               '<a href="/signup">Create account</a></nav>')
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} — CatalogIQ</title><style>
:root{{--lime:#d6ff4d;--bg:#190d27;--panel:#241536;--ink:#fff7ff;--dim:#c9b8d4;--line:#422d56}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);
font-family:Inter,system-ui,-apple-system,'Segoe UI',sans-serif}}
header{{display:flex;justify-content:space-between;align-items:center;
padding:16px 22px;border-bottom:1px solid var(--line)}}
.brand{{font-weight:950;letter-spacing:-.04em;font-size:22px;color:var(--ink);text-decoration:none}}
.brand em{{color:var(--lime);font-style:normal}}
nav a{{color:var(--dim);margin-right:16px;text-decoration:none;font-weight:700;font-size:14px}}
.linkbtn{{background:none;border:0;color:var(--dim);font-weight:700;cursor:pointer;font-size:14px}}
main{{max-width:880px;margin:0 auto;padding:28px 20px 70px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;margin:16px 0}}
h1{{font-size:32px;letter-spacing:-.03em;margin:.2em 0}}h2{{font-size:21px;letter-spacing:-.02em}}
.dim{{color:var(--dim)}}.lime{{color:var(--lime)}}
.btn{{display:inline-block;background:var(--lime);color:#23152d;font-weight:900;
padding:13px 20px;border-radius:12px;text-decoration:none;border:0;cursor:pointer;font-size:15px}}
.btn.ghost{{background:transparent;color:var(--lime);border:1px solid var(--lime)}}
label{{display:block;font-size:13px;font-weight:800;margin:14px 0 6px}}
input,select,textarea{{width:100%;padding:12px;border-radius:10px;border:1px solid var(--line);
background:#2a1939;color:var(--ink);font-size:15px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
td,th{{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
.pill{{display:inline-block;padding:4px 10px;border-radius:99px;font-size:12px;font-weight:900;
background:#3a2450;color:var(--lime)}}
.pill.warn{{background:#5a2436;color:#ffb3c2}}.pill.ok{{background:#274a1e;color:#b6ff83}}
.flag{{color:#ffb3c2;font-weight:700}}.err{{background:#5a2436;padding:12px 16px;border-radius:10px}}
.note{{background:#2e1c44;padding:12px 16px;border-radius:10px;color:var(--dim)}}
</style></head><body><header><a class="brand" href="/app">Catalog<em>IQ</em></a>{nav}</header>
<main>{body}</main></body></html>"""

def err_page(title, msg):
    return page(title, f'<div class="card"><h1>{esc(title)}</h1>'
                       f'<p class="err">{esc(msg)}</p></div>')

# --------------------------------------------------------------------------
# webhook core (shared by the real endpoint and the local stub harness)
# --------------------------------------------------------------------------
def apply_stripe_event(ev):
    """Reconcile one verified Stripe event into orders/subscriptions.
    Idempotent: webhook_events.event_id is the primary key."""
    etype = ev.get("type", "")
    obj = (ev.get("data") or {}).get("object") or {}
    try:
        db.exec("INSERT INTO webhook_events(event_id, type, received_at) "
                "VALUES(%s, %s, %s)", (ev.get("id", ""), etype, A.now_iso()))
    except Exception:
        return "duplicate"
    meta = obj.get("metadata") or {}
    ws_ref = meta.get("workspace_ref") or obj.get("client_reference_id")
    ws = db.one("SELECT * FROM workspaces WHERE ref=%s", (ws_ref,)) if ws_ref else None

    if etype == "checkout.session.completed" and ws:
        order_ref = meta.get("order_ref")
        if not order_ref:
            # Route F (Payment Links): the session carries no order metadata;
            # bind by workspace + amount to the latest matching pending order.
            pend = db.q("SELECT * FROM orders WHERE workspace_id=%s AND "
                        "status='pending' ORDER BY id DESC", (ws["id"],))
            amt = obj.get("amount_total")
            match = next((o for o in pend if amt is None
                          or o["amount_cents"] == amt), None) or (
                              pend[0] if pend else None)
            if match:
                order_ref = match["ref"]
        if order_ref:
            db.exec("UPDATE orders SET status='paid', paid_at=%s, "
                    "stripe_payment_intent=%s WHERE ref=%s",
                    (A.now_iso(), obj.get("payment_intent"), order_ref))
        db.exec("UPDATE workspaces SET stripe_customer_id=%s WHERE id=%s",
                (obj.get("customer"), ws["id"]))
        sub_id = obj.get("subscription")
        if sub_id:
            existing = db.one("SELECT id FROM subscriptions WHERE "
                              "stripe_subscription_id=%s", (sub_id,))
            if existing:
                db.exec("UPDATE subscriptions SET status='active', updated_at=%s "
                        "WHERE id=%s", (A.now_iso(), existing["id"]))
            else:
                db.exec("INSERT INTO subscriptions(workspace_id, stripe_customer_id, "
                        "stripe_subscription_id, status, updated_at) "
                        "VALUES(%s,%s,%s,'active',%s)",
                        (ws["id"], obj.get("customer"), sub_id, A.now_iso()))
            db.exec("UPDATE workspaces SET plan_state='active' WHERE id=%s", (ws["id"],))
    elif etype in ("invoice.paid", "invoice.payment_failed",
                   "customer.subscription.updated", "customer.subscription.deleted"):
        sub_id = obj.get("subscription") or obj.get("id")
        sub = db.one("SELECT * FROM subscriptions WHERE stripe_subscription_id=%s",
                     (sub_id,)) if sub_id else None
        if sub:
            status = obj.get("status") or ("canceled" if etype.endswith("deleted")
                     else "past_due" if etype == "invoice.payment_failed" else "active")
            db.exec("UPDATE subscriptions SET status=%s, updated_at=%s WHERE id=%s",
                    (status, A.now_iso(), sub["id"]))
            state = {"active": "active", "past_due": "past_due",
                     "canceled": "canceled", "unpaid": "past_due"}.get(status)
            if state:
                db.exec("UPDATE workspaces SET plan_state=%s WHERE id=%s",
                        (state, sub["workspace_id"]))
    return "applied"

# --------------------------------------------------------------------------
# side tables (file blobs keep uploads off any ephemeral filesystem)
# --------------------------------------------------------------------------
db.exec("CREATE TABLE IF NOT EXISTS file_blobs(upload_id INTEGER PRIMARY KEY, content_b64 TEXT NOT NULL)")
db.exec("CREATE TABLE IF NOT EXISTS job_rows(job_id INTEGER PRIMARY KEY, idxs_json TEXT NOT NULL)")

import base64, queue, time
_jobq = queue.Queue()

def process_job(job_id):
    job = db.one("SELECT * FROM jobs WHERE id=%s", (job_id,))
    if not job:
        return
    db.exec("UPDATE jobs SET status='running' WHERE id=%s", (job_id,))
    try:
        up = db.one("SELECT * FROM uploads WHERE id=%s", (job["upload_id"],))
        blob = db.one("SELECT content_b64 FROM file_blobs WHERE upload_id=%s",
                      (job["upload_id"],))
        data = base64.b64decode(blob["content_b64"])
        cols, rows = C.parse_upload(data, up["filename"])
        mapping = json.loads(up["mapping_json"] or "{}")
        sel = db.one("SELECT idxs_json FROM job_rows WHERE job_id=%s", (job_id,))
        idxs = json.loads(sel["idxs_json"]) if sel else list(range(len(rows)))
        db.exec("DELETE FROM drafts WHERE job_id=%s", (job_id,))  # idempotent regen
        for i in idxs:
            if i < 0 or i >= len(rows):
                continue
            title, desc, seo, facts, missing = C.compose_draft(rows[i], mapping)
            db.exec("INSERT INTO drafts(job_id, workspace_id, sku, title, description, "
                    "seo_title, facts_json, missing_json, status, created_at, updated_at) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'draft',%s,%s)",
                    (job_id, job["workspace_id"], facts.get("sku", ""), title, desc,
                     seo, json.dumps(facts), json.dumps(missing),
                     A.now_iso(), A.now_iso()))
        db.exec("UPDATE jobs SET status='completed', finished_at=%s WHERE id=%s",
                (A.now_iso(), job_id))
        db.exec("UPDATE uploads SET status='processed' WHERE id=%s", (job["upload_id"],))
    except Exception as e:
        db.exec("UPDATE jobs SET status='failed', error=%s WHERE id=%s",
                (str(e)[:400], job_id))

def _worker():
    while True:
        job_id = _jobq.get()
        try:
            process_job(job_id)
        finally:
            _jobq.task_done()

def recover_jobs():
    """Restart recovery: running jobs re-queue; drafts regenerate idempotently."""
    rows = db.q("SELECT id FROM jobs WHERE status IN ('queued','running')")
    for r in rows:
        db.exec("UPDATE jobs SET status='queued' WHERE id=%s", (r["id"],))
        _jobq.put(r["id"])

threading.Thread(target=_worker, daemon=True).start()
recover_jobs()

# --------------------------------------------------------------------------
# request handler
# --------------------------------------------------------------------------
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # -- plumbing ------------------------------------------------------------
    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, to, cookie=None):
        headers = {"Location": to}
        if cookie:
            headers["Set-Cookie"] = cookie
        self._send(303, "", headers=headers)

    def _session_cookie(self, raw):
        secure = "; Secure" if BASE.startswith("https") else ""
        return f"ciq_session={raw}; Path=/; HttpOnly; SameSite=Lax{secure}"

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _form(self):
        body = self._read_body()
        return {k: v for k, v in parse_qs(body.decode("utf-8", "replace")).items()}

    def _multipart(self):
        ctype = self.headers.get("Content-Type", "")
        m = re.search(r"boundary=(.+)", ctype)
        boundary = ("--" + m.group(1).strip()).encode()
        body = self._read_body()
        fields, files = {}, {}
        for part in body.split(boundary):
            if b"\r\n\r\n" not in part:
                continue
            head, data = part.split(b"\r\n\r\n", 1)
            data = data.rstrip(b"\r\n")
            if data.endswith(b"--"):
                data = data[:-2].rstrip(b"\r\n")
            nm = re.search(rb'name="([^"]+)"', head)
            if not nm:
                continue
            name = nm.group(1).decode()
            fn = re.search(rb'filename="([^"]*)"', head)
            if fn and fn.group(1):
                files[name] = (fn.group(1).decode(), data)
            else:
                fields[name] = data.decode("utf-8", "replace")
        return fields, files

    def _start_session(self, user_id):
        raw = A.new_token()
        db.exec("INSERT INTO sessions(token_hash, user_id, created_at, expires_at) "
                "VALUES(%s,%s,%s,%s)",
                (A.tok_hash(raw), user_id, A.now_iso(), A.expiry(24 * 14)))
        return raw

    # -- routing ---------------------------------------------------------------
    def do_GET(self):
        p = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(p.query).items()}
        route = p.path
        try:
            if route == "/":
                return self._redirect("/app")
            if route == "/signup":
                return self._send(200, self._signup_page(q))
            if route == "/login":
                return self._send(200, self._login_page(q))
            if route == "/verify":
                return self._verify(q)
            if route == "/forgot":
                return self._send(200, self._forgot_page())
            if route == "/reset":
                return self._send(200, self._reset_page(q))
            if route == "/stub-checkout":
                if not (S.stub_mode and S.ALLOW_STUB):
                    return self._send(404, err_page("Not found", "That page does not exist."))
                return self._stub_checkout(q)
            user, raw = get_user(self)
            if not user:
                return self._redirect("/login")
            ws = workspace_of(user)
            if route == "/app":
                return self._send(200, self._dashboard(user, ws, raw, q))
            if route == "/app/upload":
                return self._send(200, self._upload_page(user, ws, raw, q))
            if route.startswith("/app/upload/"):
                return self._upload_detail(user, ws, raw, route, q)
            if route == "/app/drafts":
                return self._send(200, self._drafts_page(user, ws, raw, q))
            if route.startswith("/app/draft/"):
                return self._draft_detail(user, ws, raw, route)
            if route == "/app/export":
                return self._export(user, ws, q)
            if route == "/app/billing":
                return self._send(200, self._billing_page(user, ws, raw, q))
            if route == "/billing/return":
                return self._send(200, self._billing_return(user, ws, raw, q))
            return self._send(404, err_page("Not found", "That page does not exist."))
        except Exception as e:
            return self._send(500, err_page("Something broke", str(e)[:300]))

    def do_POST(self):
        p = urlparse(self.path)
        route = p.path
        try:
            if route == "/webhooks/stripe":
                return self._webhook()
            if route == "/signup":
                return self._do_signup()
            if route == "/login":
                return self._do_login()
            if route == "/forgot":
                return self._do_forgot()
            if route == "/reset":
                return self._do_reset()
            if route == "/stub/pay":
                if not (S.stub_mode and S.ALLOW_STUB):
                    return self._send(404, err_page("Not found", "That page does not exist."))
                return self._stub_pay()
            user, raw = get_user(self)
            if not user:
                return self._redirect("/login")
            ws = workspace_of(user)
            form = None
            if route == "/logout":
                form = self._form()
                if not check_csrf(self, form):
                    return self._send(403, err_page("Blocked", "CSRF check failed."))
                db.exec("DELETE FROM sessions WHERE token_hash=%s",
                        (A.tok_hash(raw),))
                return self._redirect("/login",
                                      "ciq_session=; Path=/; Max-Age=0")
            if route == "/app/upload":
                return self._do_upload(user, ws, raw)
            if route.startswith("/app/upload/"):
                return self._upload_action(user, ws, raw, route)
            if route.startswith("/app/draft/"):
                return self._draft_action(user, ws, raw, route)
            if route == "/app/billing/checkout":
                form = self._form()
                if not check_csrf(self, form):
                    return self._send(403, err_page("Blocked", "CSRF check failed."))
                return self._do_checkout(user, ws, form)
            if route == "/app/billing/portal":
                form = self._form()
                if not check_csrf(self, form):
                    return self._send(403, err_page("Blocked", "CSRF check failed."))
                return self._redirect(S.create_portal(BASE, ws.get("stripe_customer_id")))
            return self._send(404, err_page("Not found", "That page does not exist."))
        except Exception as e:
            return self._send(500, err_page("Something broke", str(e)[:300]))

    # -- auth pages/actions ----------------------------------------------------
    def _signup_page(self, q):
        plan = q.get("plan", "")
        plan_note = ""
        if plan in S.PLANS:
            plan_note = (f'<p class="note">Selected plan: <b>{S.PLANS[plan]["name"]} '
                         f'· {S.PLANS[plan]["price"]}</b> — you will confirm payment '
                         f'after your account exists. Nothing is charged now.</p>')
        body = f"""<div class="card"><h1>Create your CatalogIQ account</h1>
        <p class="dim">Your account creates your pilot workspace immediately.
        Start with the free 25-SKU sample pack — facts locked to your data,
        nothing published without your approval.</p>{plan_note}
        <form method="post" action="/signup">
        <input type="hidden" name="plan" value="{esc(plan)}">
        <label>Work email</label><input required type="email" name="email" autocomplete="email">
        <label>Password (10+ characters)</label><input required type="password" name="password" minlength="10" autocomplete="new-password">
        <label>Store / company name</label><input required name="store_name">
        <label>Catalog size</label><select name="catalog_size" required>
        <option value="">Choose approximate size</option><option>Under 100 SKUs</option>
        <option>100–1,000 SKUs</option><option>1,000–10,000 SKUs</option>
        <option>10,000+ SKUs</option></select>
        <p><button class="btn" type="submit">Create account + workspace</button></p>
        </form><p class="dim">Already have an account? <a class="lime" href="/login">Sign in</a></p></div>"""
        return page("Create account", body)

    def _do_signup(self):
        if not rate_ok("signup:" + (self.client_address[0] or "")):
            return self._send(429, err_page("Slow down", "Too many attempts — try again shortly."))
        form = self._form()
        email = form.get("email", [""])[0].strip().lower()
        pw = form.get("password", [""])[0]
        store = form.get("store_name", [""])[0].strip()
        size = form.get("catalog_size", [""])[0]
        plan = form.get("plan", [""])[0]
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) or len(pw) < 10 or not store:
            return self._send(400, err_page("Check the form",
                              "A valid email, a 10+ character password, and your store name are required."))
        if db.one("SELECT id FROM users WHERE email=%s", (email,)):
            return self._send(400, err_page("Account exists",
                              "That email already has an account — sign in instead."))
        uid = db.exec("INSERT INTO users(email, pw_hash, email_verified, created_at) "
                      "VALUES(%s,%s,0,%s)", (email, A.hash_password(pw), A.now_iso()))
        if uid is None:  # neon backend: fetch back
            uid = db.one("SELECT id FROM users WHERE email=%s", (email,))["id"]
        seq = db.next_seq("workspace")
        ref = ref_for(seq)
        db.exec("INSERT INTO workspaces(user_id, ref, store_name, catalog_size, plan, "
                "plan_state, created_at) VALUES(%s,%s,%s,%s,%s,'sample',%s)",
                (uid, ref, store, size, plan if plan in S.PLANS else "", A.now_iso()))
        tok = A.new_token()
        db.exec("INSERT INTO tokens(user_id, kind, token_hash, expires_at) VALUES(%s,'verify',%s,%s)",
                (uid, A.tok_hash(tok), A.expiry(48)))
        M.send(email, "Welcome to CatalogIQ — verify your email",
               f"Welcome to CatalogIQ.\n\nYour pilot workspace is created.\n"
               f"Workspace reference: {ref}\nStore: {store}\n\n"
               f"Verify your email to unlock your free 25-SKU sample pack and billing:\n"
               f"{BASE}/verify?token={tok}\n\n"
               f"Facts locked to your data — nothing is ever invented, and nothing "
               f"publishes without your approval.\n— CatalogIQ (an Apex Grid Engineering PLLC company)")
        raw = self._start_session(uid)
        return self._redirect("/app?welcome=1", self._session_cookie(raw))

    def _verify(self, q):
        tok = q.get("token", "")
        row = db.one("SELECT * FROM tokens WHERE token_hash=%s AND kind='verify' "
                     "AND used_at IS NULL", (A.tok_hash(tok),))
        if not row or A.is_expired(row["expires_at"]):
            return self._send(400, err_page("Link expired",
                              "That verification link is invalid or expired — sign in and request a new one."))
        db.exec("UPDATE tokens SET used_at=%s WHERE id=%s", (A.now_iso(), row["id"]))
        db.exec("UPDATE users SET email_verified=1 WHERE id=%s", (row["user_id"],))
        return self._send(200, page("Email verified",
            '<div class="card"><h1>Email verified ✓</h1><p>Your free 25-SKU sample '
            'pack and billing are unlocked.</p><p><a class="btn" href="/app">Open your workspace</a></p></div>'))

    def _login_page(self, q):
        note = '<p class="note">Signed out. See you soon.</p>' if q.get("bye") else ""
        body = f"""<div class="card"><h1>Sign in</h1>{note}
        <form method="post" action="/login">
        <label>Work email</label><input required type="email" name="email" autocomplete="email">
        <label>Password</label><input required type="password" name="password" autocomplete="current-password">
        <p><button class="btn" type="submit">Sign in</button></p></form>
        <p class="dim"><a class="lime" href="/forgot">Forgot password?</a> ·
        <a class="lime" href="/signup">Create an account</a></p></div>"""
        return page("Sign in", body)

    def _do_login(self):
        if not rate_ok("login:" + (self.client_address[0] or "")):
            return self._send(429, err_page("Slow down", "Too many attempts — try again shortly."))
        form = self._form()
        email = form.get("email", [""])[0].strip().lower()
        user = db.one("SELECT * FROM users WHERE email=%s", (email,))
        if not user or not A.check_password(form.get("password", [""])[0], user["pw_hash"]):
            return self._send(401, err_page("Sign-in failed", "Email or password did not match."))
        raw = self._start_session(user["id"])
        return self._redirect("/app", self._session_cookie(raw))

    def _forgot_page(self):
        return page("Reset password", """<div class="card"><h1>Reset your password</h1>
        <form method="post" action="/forgot"><label>Work email</label>
        <input required type="email" name="email">
        <p><button class="btn" type="submit">Email me a reset link</button></p></form></div>""")

    def _do_forgot(self):
        form = self._form()
        email = form.get("email", [""])[0].strip().lower()
        user = db.one("SELECT * FROM users WHERE email=%s", (email,))
        if user:
            tok = A.new_token()
            db.exec("INSERT INTO tokens(user_id, kind, token_hash, expires_at) "
                    "VALUES(%s,'reset',%s,%s)", (user["id"], A.tok_hash(tok), A.expiry(2)))
            M.send(email, "CatalogIQ — password reset",
                   f"Reset your CatalogIQ password:\n{BASE}/reset?token={tok}\n"
                   f"This link expires in 2 hours. If you did not request it, ignore this email.")
        return self._send(200, page("Check your email",
            '<div class="card"><h1>Check your email</h1><p>If that address has an '
            'account, a reset link is on its way.</p></div>'))

    def _reset_page(self, q):
        tok = esc(q.get("token", ""))
        return page("Set a new password", f"""<div class="card"><h1>Set a new password</h1>
        <form method="post" action="/reset"><input type="hidden" name="token" value="{tok}">
        <label>New password (10+ characters)</label>
        <input required type="password" name="password" minlength="10">
        <p><button class="btn" type="submit">Set password</button></p></form></div>""")

    def _do_reset(self):
        form = self._form()
        row = db.one("SELECT * FROM tokens WHERE token_hash=%s AND kind='reset' "
                     "AND used_at IS NULL", (A.tok_hash(form.get("token", [""])[0]),))
        pw = form.get("password", [""])[0]
        if not row or A.is_expired(row["expires_at"]) or len(pw) < 10:
            return self._send(400, err_page("Link expired", "That reset link is invalid or expired."))
        db.exec("UPDATE tokens SET used_at=%s WHERE id=%s", (A.now_iso(), row["id"]))
        db.exec("UPDATE users SET pw_hash=%s WHERE id=%s",
                (A.hash_password(pw), row["user_id"]))
        db.exec("DELETE FROM sessions WHERE user_id=%s", (row["user_id"],))
        return self._redirect("/login")

    # -- stripe webhook + stub ---------------------------------------------------
    def _webhook(self):
        payload = self._read_body()
        sig = self.headers.get("Stripe-Signature", "")
        if not S.verify_webhook(payload, sig):
            return self._send(400, json.dumps({"error": "bad signature"}),
                              "application/json")
        ev = json.loads(payload.decode())
        result = apply_stripe_event(ev)
        return self._send(200, json.dumps({"received": True, "result": result}),
                          "application/json")

    def _stub_checkout(self, q):
        order = esc(q.get("order", ""))
        plan = esc(q.get("plan", ""))
        return self._send(200, page("Test checkout (stub)",
            f'<div class="card"><h1>Stripe test checkout — STUB</h1>'
            f'<p class="dim">Local proof harness only. Order {order} · plan {plan}.</p>'
            f'<form method="post" action="/stub/pay">'
            f'<input type="hidden" name="order" value="{order}">'
            f'<input type="hidden" name="plan" value="{plan}">'
            f'<button class="btn" type="submit">Pay (simulate success)</button></form></div>'))

    def _stub_pay(self):
        form = self._form()
        order_ref = form.get("order", [""])[0]
        order = db.one("SELECT o.*, w.ref AS ws_ref FROM orders o "
                       "JOIN workspaces w ON w.id=o.workspace_id WHERE o.ref=%s",
                       (order_ref,))
        if not order:
            return self._send(404, err_page("No order", "Unknown order reference."))
        ev = {"id": f"evt_stub_{order_ref}", "type": "checkout.session.completed",
              "data": {"object": {
                  "id": f"cs_stub_{order_ref}", "customer": "cus_stub",
                  "subscription": f"sub_stub_{order_ref}",
                  "payment_intent": "pi_stub",
                  "client_reference_id": order["ws_ref"],
                  "metadata": {"workspace_ref": order["ws_ref"],
                               "order_ref": order_ref}}}}
        apply_stripe_event(ev)
        return self._redirect(f"/billing/return?order={order_ref}")

    # -- workspace dashboard (the confirmation surface) -------------------------
    def _dashboard(self, user, ws, raw, q):
        sub = db.one("SELECT * FROM subscriptions WHERE workspace_id=%s "
                     "ORDER BY id DESC LIMIT 1", (ws["id"],))
        last_order = db.one("SELECT * FROM orders WHERE workspace_id=%s "
                            "ORDER BY id DESC LIMIT 1", (ws["id"],))
        uploads = db.q("SELECT * FROM uploads WHERE workspace_id=%s ORDER BY id DESC",
                       (ws["id"],))
        verified = bool(user["email_verified"])
        plan_label = S.PLANS.get(ws.get("plan") or "", {}).get("name", "—")
        state = ws["plan_state"]
        state_pill = {"sample": '<span class="pill">SAMPLE</span>',
                      "active": '<span class="pill ok">ACTIVE</span>',
                      "past_due": '<span class="pill warn">PAST DUE</span>',
                      "canceled": '<span class="pill warn">CANCELED</span>'}.get(state, state)
        if not verified:
            next_step = ('<p class="note"><b>Next: verify your email.</b> We sent a '
                         'verification link to ' + esc(user["email"]) + '. Verification '
                         'unlocks your free sample pack and billing.</p>')
        elif not uploads:
            next_step = ('<p class="note"><b>Next: upload your supplier catalog</b> '
                         '(CSV or XLSX). We identify missing facts, prepare reviewable '
                         'drafts, and keep everything unpublished until you approve it.</p>')
        elif state == "sample" and ws["sample_used"]:
            next_step = ('<p class="note"><b>Next: choose a plan</b> to process your '
                         'full catalog — your sample drafts stay in this workspace.</p>')
        else:
            next_step = '<p class="note"><b>Next:</b> review your drafts under <b>Drafts</b>.</p>'
        welcome = '<p class="note">Workspace created ✓ — this page is your confirmation. Your reference is below.</p>' if q.get("welcome") else ""
        body = f"""<div class="card"><h1>Your CatalogIQ workspace</h1>{welcome}
        <table>
        <tr><td class="dim">Workspace reference</td><td><b>{esc(ws['ref'])}</b></td></tr>
        <tr><td class="dim">Store</td><td>{esc(ws['store_name'])}</td></tr>
        <tr><td class="dim">Status</td><td>{state_pill}</td></tr>
        <tr><td class="dim">Selected plan</td><td>{esc(plan_label)}</td></tr>
        <tr><td class="dim">Payment</td><td>{esc('Confirmed — ' + last_order['ref']) if last_order and last_order['status'] == 'paid' else ('Not yet — no charge has been made' if not last_order else esc(last_order['status']))}</td></tr>
        <tr><td class="dim">Catalog</td><td>{len(uploads)} file(s) uploaded</td></tr>
        <tr><td class="dim">Free sample</td><td>{'Used' if ws['sample_used'] else 'Available — 25 SKUs, free'}</td></tr>
        </table>{next_step}
        <p><a class="btn" href="/app/upload">Upload your supplier catalog</a>
        <a class="btn ghost" href="/app/billing">Plans &amp; billing</a></p></div>"""
        return page("Your workspace", body, user, raw)

    # -- uploads -------------------------------------------------------------------
    def _upload_page(self, user, ws, raw, q):
        ups = db.q("SELECT * FROM uploads WHERE workspace_id=%s ORDER BY id DESC",
                   (ws["id"],))
        rows = "".join(
            f'<tr><td>{esc(u["filename"])}</td><td>{u["rows_total"]} rows</td>'
            f'<td>{esc(u["status"])}</td>'
            f'<td><a class="lime" href="/app/upload/{u["id"]}">Open</a></td></tr>'
            for u in ups)
        body = f"""<div class="card"><h1>Upload your supplier catalog</h1>
        <p class="dim">CSV or XLSX, up to 10 MB. Your file is stored against your
        workspace only. We never invent a product fact: missing attributes are
        flagged on the draft, in plain sight.</p>
        <form method="post" action="/app/upload" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="{csrf_of(raw)}">
        <label>Catalog file</label><input required type="file" name="catalog" accept=".csv,.xlsx,.txt">
        <p><button class="btn" type="submit">Upload + read file</button></p></form></div>
        <div class="card"><h2>Your uploads</h2><table>{rows or '<tr><td class="dim">None yet.</td></tr>'}</table></div>"""
        return page("Upload catalog", body, user, raw)

    def _do_upload(self, user, ws, raw):
        fields, files = self._multipart()
        if fields.get("csrf") != csrf_of(raw):
            return self._send(403, err_page("Blocked", "CSRF check failed."))
        if "catalog" not in files:
            return self._send(400, err_page("No file", "Choose a CSV or XLSX file."))
        filename, data = files["catalog"]
        if len(data) > MAX_UPLOAD:
            return self._send(400, err_page("Too large", "Files are limited to 10 MB."))
        try:
            cols, rows = C.parse_upload(data, filename)
        except Exception as e:
            return self._send(400, err_page("Could not read that file",
                              f"We could not parse it as CSV/XLSX ({esc(str(e)[:120])})."))
        if not cols or not rows:
            return self._send(400, err_page("Empty file", "No data rows were found."))
        mapping = C.guess_mapping(cols)
        uid = db.exec("INSERT INTO uploads(workspace_id, filename, rows_total, "
                      "columns_json, mapping_json, status, created_at) "
                      "VALUES(%s,%s,%s,%s,%s,'uploaded',%s)",
                      (ws["id"], filename, len(rows), json.dumps(cols),
                       json.dumps(mapping), A.now_iso()))
        if uid is None:
            uid = db.one("SELECT id FROM uploads WHERE workspace_id=%s ORDER BY id DESC "
                         "LIMIT 1", (ws["id"],))["id"]
        db.exec("INSERT INTO file_blobs(upload_id, content_b64) VALUES(%s,%s)",
                (uid, base64.b64encode(data).decode()))
        return self._redirect(f"/app/upload/{uid}")

    def _upload_detail(self, user, ws, raw, route, q):
        uid = int(route.rsplit("/", 1)[1])
        up = db.one("SELECT * FROM uploads WHERE id=%s AND workspace_id=%s",
                    (uid, ws["id"]))
        if not up:
            return self._send(404, err_page("Not found", "That upload is not in your workspace."))
        cols = json.loads(up["columns_json"])
        mapping = json.loads(up["mapping_json"] or "{}")
        opts = lambda cur: "".join(
            f'<option value="{esc(c)}"{" selected" if c == cur else ""}>{esc(c)}</option>'
            for c in [""] + cols)
        fields = "".join(
            f'<label>{esc(canon)}</label><select name="map_{esc(canon)}">{opts(mapping.get(canon, ""))}</select>'
            for canon in C.CANONICAL)
        blob = db.one("SELECT content_b64 FROM file_blobs WHERE upload_id=%s", (uid,))
        _, rows = C.parse_upload(base64.b64decode(blob["content_b64"]), up["filename"])
        preview = rows[:30]
        checks = "".join(
            f'<tr><td><input type="checkbox" name="row" value="{i}" checked></td>'
            f'<td>{i + 1}</td><td>{esc(" · ".join(str(v) for v in list(r.values())[:3]))}</td></tr>'
            for i, r in enumerate(preview))
        sample_btn = ""
        if not ws["sample_used"]:
            sample_btn = (f'<button class="btn" type="submit" name="kind" value="sample">'
                          f'Run free sample (up to 25 selected rows)</button>')
        full_btn = ""
        if ws["plan_state"] == "active":
            full_btn = (f'<button class="btn ghost" type="submit" name="kind" value="full">'
                        f'Process all {len(rows)} rows (plan)</button>')
        body = f"""<div class="card"><h1>{esc(up['filename'])}</h1>
        <p class="dim">{len(rows)} rows read. Confirm the field mapping — the left
        side is what CatalogIQ drafts from; the right side is your file's column.</p>
        <form method="post" action="/app/upload/{uid}/mapping">
        <input type="hidden" name="csrf" value="{csrf_of(raw)}">{fields}
        <p><button class="btn ghost" type="submit">Save mapping</button></p></form></div>
        <div class="card"><h2>Choose rows</h2>
        <form method="post" action="/app/upload/{uid}/run">
        <input type="hidden" name="csrf" value="{csrf_of(raw)}">
        <table>{checks}</table>
        <p class="dim">Showing the first 30 rows for selection. The free sample
        processes up to 25 — you choose which; nothing is picked silently.</p>
        <p>{sample_btn} {full_btn}</p></form></div>"""
        return self._send(200, page("Upload detail", body, user, raw))

    def _upload_action(self, user, ws, raw, route):
        parts = route.strip("/").split("/")
        uid = int(parts[2])
        action = parts[3]
        up = db.one("SELECT * FROM uploads WHERE id=%s AND workspace_id=%s",
                    (uid, ws["id"]))
        if not up:
            return self._send(404, err_page("Not found", "That upload is not in your workspace."))
        if action == "mapping":
            raw_form = self._form()
            form = {k: v[0] if v else "" for k, v in raw_form.items()}
            if form.get("csrf") != csrf_of(raw):
                return self._send(403, err_page("Blocked", "CSRF check failed."))
            mapping = {c: form.get(f"map_{c}", "") for c in C.CANONICAL}
            mapping = {k: v for k, v in mapping.items() if v}
            db.exec("UPDATE uploads SET mapping_json=%s, status='mapped' WHERE id=%s",
                    (json.dumps(mapping), uid))
            return self._redirect(f"/app/upload/{uid}")
        if action == "run":
            form = self._form()
            if not check_csrf(self, form):
                return self._send(403, err_page("Blocked", "CSRF check failed."))
            kind = form.get("kind", ["sample"])[0]
            idxs = [int(x) for x in form.get("row", [])]
            if kind == "sample":
                if not user["email_verified"]:
                    return self._send(400, err_page("Verify first",
                        "Verify your email to run the free sample pack."))
                if ws["sample_used"]:
                    return self._send(400, err_page("Sample used",
                        "Your free sample is used — a plan processes the full catalog."))
                idxs = idxs[:25]
                if not idxs:
                    return self._send(400, err_page("No rows", "Select at least one row."))
                db.exec("UPDATE workspaces SET sample_used=1 WHERE id=%s", (ws["id"],))
            else:
                if ws["plan_state"] != "active":
                    return self._send(400, err_page("Plan required",
                        "An active plan is required to process a full catalog."))
                blob = db.one("SELECT content_b64 FROM file_blobs WHERE upload_id=%s", (uid,))
                _, allrows = C.parse_upload(base64.b64decode(blob["content_b64"]),
                                            up["filename"])
                cap = S.PLANS.get(ws.get("plan") or "starter", {}).get("sku_cap", 500)
                idxs = list(range(min(len(allrows), cap)))
            jid = db.exec("INSERT INTO jobs(workspace_id, upload_id, kind, rows_selected, "
                          "status, created_at) VALUES(%s,%s,%s,%s,'queued',%s)",
                          (ws["id"], uid, kind, len(idxs), A.now_iso()))
            if jid is None:
                jid = db.one("SELECT id FROM jobs WHERE workspace_id=%s ORDER BY id DESC "
                             "LIMIT 1", (ws["id"],))["id"]
            db.exec("INSERT INTO job_rows(job_id, idxs_json) VALUES(%s,%s)",
                    (jid, json.dumps(idxs)))
            _jobq.put(jid)
            return self._redirect(f"/app/drafts?job={jid}")
        return self._send(404, err_page("Not found", "Unknown action."))

    # -- drafts -----------------------------------------------------------------------
    def _drafts_page(self, user, ws, raw, q):
        jobs = db.q("SELECT * FROM jobs WHERE workspace_id=%s ORDER BY id DESC",
                    (ws["id"],))
        out = ['<div class="card"><h1>Listing drafts</h1>']
        for j in jobs:
            drafts = db.q("SELECT * FROM drafts WHERE job_id=%s ORDER BY id", (j["id"],))
            out.append(f'<h2>Job #{j["id"]} — {esc(j["kind"])} · {esc(j["status"])}'
                       f' · {len(drafts)} drafts</h2>')
            if j["status"] in ("queued", "running"):
                out.append('<p class="note">Processing — refresh in a few seconds.</p>')
            if j["status"] == "failed":
                out.append(f'<p class="err">Failed: {esc(j["error"] or "")}</p>')
            for d in drafts:
                miss = json.loads(d["missing_json"] or "[]")
                flags = ("<span class='flag'>Missing facts (not invented): "
                         + ", ".join(miss) + "</span>") if miss else \
                        "<span class='lime'>All key facts supplied</span>"
                out.append(
                    f'<p><a class="lime" href="/app/draft/{d["id"]}">{esc(d["title"])}</a>'
                    f' · <span class="pill">{esc(d["status"])}</span><br>{flags}</p>')
            if drafts:
                out.append(f'<p><a class="btn ghost" href="/app/export?job={j["id"]}">'
                           f'Export job #{j["id"]} as CSV</a></p>')
        out.append("</div>")
        return page("Drafts", "".join(out), user, raw)

    def _draft_detail(self, user, ws, raw, route):
        did = int(route.rsplit("/", 1)[1])
        d = db.one("SELECT * FROM drafts WHERE id=%s AND workspace_id=%s",
                   (did, ws["id"]))
        if not d:
            return self._send(404, err_page("Not found", "That draft is not in your workspace."))
        facts = json.loads(d["facts_json"] or "{}")
        miss = json.loads(d["missing_json"] or "[]")
        fact_rows = "".join(f"<tr><td class='dim'>{esc(k)}</td><td>{esc(v) or '<span class=flag>— missing, flagged not invented</span>'}</td></tr>"
                            for k, v in facts.items())
        body = f"""<div class="card"><h1>{esc(d['title'])}</h1>
        <p><span class="pill">{esc(d['status'])}</span></p>
        <h2>Source facts (exactly as supplied)</h2><table>{fact_rows}</table>
        <p class="flag">{('Missing: ' + ', '.join(miss)) if miss else ''}</p>
        <form method="post" action="/app/draft/{did}">
        <input type="hidden" name="csrf" value="{csrf_of(raw)}">
        <label>Listing title</label><input name="title" value="{esc(d['title'])}">
        <label>Description</label><textarea name="description" rows="8">{esc(d['description'])}</textarea>
        <label>SEO title</label><input name="seo_title" value="{esc(d['seo_title'])}">
        <p><button class="btn ghost" type="submit" name="act" value="save">Save edits</button>
        <button class="btn" type="submit" name="act" value="approve">Approve listing</button></p>
        </form><p class="dim">Approving records your approval in this workspace.
        Nothing publishes anywhere automatically.</p></div>"""
        return self._send(200, page("Draft", body, user, raw))

    def _draft_action(self, user, ws, raw, route):
        did = int(route.rsplit("/", 1)[1])
        form = self._form()
        if not check_csrf(self, form):
            return self._send(403, err_page("Blocked", "CSRF check failed."))
        d = db.one("SELECT * FROM drafts WHERE id=%s AND workspace_id=%s",
                   (did, ws["id"]))
        if not d:
            return self._send(404, err_page("Not found", "That draft is not in your workspace."))
        act = form.get("act", ["save"])[0]
        status = "approved" if act == "approve" else "edited"
        db.exec("UPDATE drafts SET title=%s, description=%s, seo_title=%s, status=%s, "
                "updated_at=%s WHERE id=%s",
                (form.get("title", [""])[0], form.get("description", [""])[0],
                 form.get("seo_title", [""])[0], status, A.now_iso(), did))
        return self._redirect(f"/app/draft/{did}")

    def _export(self, user, ws, q):
        jid = int(q.get("job", "0"))
        drafts = db.q("SELECT * FROM drafts WHERE job_id=%s AND workspace_id=%s "
                      "ORDER BY id", (jid, ws["id"]))
        if not drafts:
            return self._send(404, err_page("Nothing to export", "No drafts for that job."))
        import csv as _csv
        buf = io.StringIO()
        w = _csv.writer(buf)
        w.writerow(["sku", "title", "description", "seo_title", "status",
                    "missing_facts"])
        for d in drafts:
            w.writerow([d["sku"], d["title"], d["description"], d["seo_title"],
                        d["status"], ";".join(json.loads(d["missing_json"] or "[]"))])
        db.exec("INSERT INTO exports(workspace_id, job_id, format, created_at) "
                "VALUES(%s,%s,'csv',%s)", (ws["id"], jid, A.now_iso()))
        return self._send(200, buf.getvalue(), "text/csv",
                          {"Content-Disposition": f'attachment; filename="catalogiq-job-{jid}.csv"'})

    # -- billing -------------------------------------------------------------------------
    def _billing_page(self, user, ws, raw, q):
        if q.get("pay") == "configuring":
            return page("Payments are being configured",
                '<div class="card"><h1>Payments are being configured</h1>'
                '<p>Checkout opens shortly — your order reference is saved as '
                'pending and nothing was charged. Your workspace and free '
                '25-SKU sample work right now.</p>'
                '<p><a href="/app">Back to your workspace</a></p></div>',
                user, raw)
        sub = db.one("SELECT * FROM subscriptions WHERE workspace_id=%s ORDER BY id "
                     "DESC LIMIT 1", (ws["id"],))
        orders = db.q("SELECT * FROM orders WHERE workspace_id=%s ORDER BY id DESC",
                      (ws["id"],))
        plan_cards = "".join(
            f'<div class="card"><h2>{p["name"]} — {p["price"]}</h2>'
            f'<p class="dim">Up to {p["sku_cap"]:,} SKUs. Fact-locked drafts, '
            f'review + approval before anything publishes.</p>'
            f'<form method="post" action="/app/billing/checkout">'
            f'<input type="hidden" name="csrf" value="{csrf_of(raw)}">'
            f'<input type="hidden" name="plan" value="{k}">'
            f'<button class="btn" type="submit">Start with {p["name"]}</button></form></div>'
            for k, p in S.PLANS.items())
        order_rows = "".join(
            f'<tr><td>{esc(o["ref"])}</td><td>{esc(o["plan"] or "")}</td>'
            f'<td>{esc(o["status"])}</td><td>{esc(o["created_at"][:10])}</td></tr>'
            for o in orders)
        sub_line = (f'Subscription: {esc(sub["status"])} · renews '
                    f'{esc((sub["current_period_end"] or "")[:10])}') if sub else \
                   'No subscription yet.'
        portal = ""
        if ws.get("stripe_customer_id"):
            if S.KEY:
                portal = (f'<form method="post" action="/app/billing/portal">'
                          f'<input type="hidden" name="csrf" value="{csrf_of(raw)}">'
                          f'<button class="btn ghost" type="submit">Manage billing / cancel '
                          f'(Stripe portal)</button></form>')
            else:
                portal = ('<p class="dim">To change or cancel your plan, use the '
                          'manage link in any Stripe receipt email, or write '
                          'info@catalogiqhq.com — changes are applied the same '
                          'business day.</p>')
        body = f"""<div class="card"><h1>Plans &amp; billing</h1>
        <p>Workspace <b>{esc(ws['ref'])}</b> · status <b>{esc(ws['plan_state'])}</b></p>
        <p class="dim">{sub_line}</p>{portal}
        <h2>Your orders</h2><table>{order_rows or '<tr><td class="dim">No orders yet.</td></tr>'}</table></div>
        {plan_cards}
        <div class="card"><h2>ShopTranslate — +$79/mo per language</h2>
        <p class="dim">Add translation for a store language after your plan is active —
        ask us from your workspace email and we attach it to your subscription.</p>
        <h2>Catalog Studio — scoped, from $999</h2>
        <p class="dim">Migrations and white-glove catalog work are scoped per project
        and invoiced — never a surprise subscription.</p></div>"""
        return page("Billing", body, user, raw)

    def _do_checkout(self, user, ws, form):
        plan = form.get("plan", [""])[0]
        if plan not in S.PLANS:
            return self._send(400, err_page("Pick a plan", "That plan is not available."))
        if not user["email_verified"]:
            return self._send(400, err_page("Verify first",
                "Verify your email before billing — your purchase must attach to a "
                "verified account so it can never be orphaned."))
        seq = db.next_seq("order")
        oref = ref_for(seq, "ORD")
        amount = {"starter": 9900, "growth": 19900, "scale": 39900}[plan]
        oid = db.exec("INSERT INTO orders(workspace_id, ref, kind, plan, amount_cents, "
                      "status, created_at) VALUES(%s,%s,'subscription',%s,%s,'pending',%s)",
                      (ws["id"], oref, plan, amount, A.now_iso()))
        db.exec("UPDATE workspaces SET plan=%s WHERE id=%s", (plan, ws["id"]))
        url, sess = S.create_checkout(BASE, ws["ref"], oref, plan, user["email"])
        db.exec("UPDATE orders SET stripe_checkout_session_id=%s WHERE ref=%s",
                (sess, oref))
        return self._redirect(url)

    def _billing_return(self, user, ws, raw, q):
        oref = q.get("order", "")
        order = db.one("SELECT * FROM orders WHERE ref=%s AND workspace_id=%s",
                       (oref, ws["id"]))
        if not order:
            return self._send(404, err_page("No order", "Unknown order reference."))
        if order["status"] == "paid":
            body = f"""<div class="card"><h1>Payment confirmed ✓</h1>
            <table><tr><td class="dim">Workspace reference</td><td><b>{esc(ws['ref'])}</b></td></tr>
            <tr><td class="dim">Order</td><td>{esc(order['ref'])}</td></tr>
            <tr><td class="dim">Plan</td><td>{esc(S.PLANS.get(order['plan'], {}).get('name', order['plan']))} — active</td></tr>
            <tr><td class="dim">Catalog</td><td>Ready for upload</td></tr></table>
            <p class="note"><b>Next: upload your supplier catalog.</b> Drafts are
            prepared from your facts only, and nothing publishes without your approval.</p>
            <p><a class="btn" href="/app/upload">Upload your catalog</a></p></div>"""
        else:
            body = f"""<div class="card"><h1>Payment processing — checking activation</h1>
            <p>Order <b>{esc(order['ref'])}</b> is not confirmed yet. Activation lands
            the moment Stripe's confirmation reaches us — this page never guesses.
            Refresh in a few seconds, or open your workspace; the state there is the
            source of truth.</p><p><a class="btn" href="/app">Open workspace</a></p></div>"""
        return page("Payment status", body, user, raw)


import io  # noqa: E402  (used by _export)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8077"))
    print(f"CatalogIQ app on :{port} (stripe stub_mode={S.stub_mode})")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
