"""CatalogIQ app — persistence layer.

Two backends behind one interface:
  - sqlite  (stdlib) — local dev + tests. DATABASE_URL unset or sqlite:///path.
  - neon    — production: Neon Postgres over its HTTPS SQL endpoint, stdlib
              urllib only. DATABASE_URL=postgres://... selects it; the host's
              /sql endpoint receives parameterized queries.

The app never speaks SQL outside this module except through q()/one()/exec().
Placeholders are written as %s in app code; the sqlite backend translates to ?.
"""
import os, json, sqlite3, urllib.request, urllib.error

SCHEMA = [
"""CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT)""",
"""CREATE TABLE IF NOT EXISTS workspaces(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE NOT NULL,
  ref TEXT UNIQUE NOT NULL,
  store_name TEXT NOT NULL DEFAULT '',
  catalog_size TEXT NOT NULL DEFAULT '',
  plan TEXT NOT NULL DEFAULT '',
  plan_state TEXT NOT NULL DEFAULT 'sample',
  sample_used INTEGER NOT NULL DEFAULT 0,
  stripe_customer_id TEXT,
  created_at TEXT NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS subscriptions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER NOT NULL,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT UNIQUE,
  price_id TEXT,
  plan TEXT,
  status TEXT,
  current_period_end TEXT,
  updated_at TEXT)""",
"""CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER NOT NULL,
  ref TEXT UNIQUE NOT NULL,
  kind TEXT NOT NULL DEFAULT 'subscription',
  plan TEXT,
  amount_cents INTEGER,
  status TEXT NOT NULL DEFAULT 'pending',
  stripe_checkout_session_id TEXT,
  stripe_payment_intent TEXT,
  created_at TEXT NOT NULL,
  paid_at TEXT)""",
"""CREATE TABLE IF NOT EXISTS uploads(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  stored_path TEXT,
  rows_total INTEGER NOT NULL DEFAULT 0,
  columns_json TEXT NOT NULL DEFAULT '[]',
  mapping_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'uploaded',
  created_at TEXT NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER NOT NULL,
  upload_id INTEGER NOT NULL,
  kind TEXT NOT NULL DEFAULT 'sample',
  rows_selected INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'queued',
  error TEXT,
  created_at TEXT NOT NULL,
  finished_at TEXT)""",
"""CREATE TABLE IF NOT EXISTS drafts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  workspace_id INTEGER NOT NULL,
  sku TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  seo_title TEXT NOT NULL DEFAULT '',
  facts_json TEXT NOT NULL DEFAULT '{}',
  missing_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'draft',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS exports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id INTEGER NOT NULL,
  job_id INTEGER,
  format TEXT NOT NULL DEFAULT 'csv',
  stored_path TEXT,
  created_at TEXT NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS webhook_events(
  event_id TEXT PRIMARY KEY,
  type TEXT,
  received_at TEXT NOT NULL)""",
"""CREATE TABLE IF NOT EXISTS counters(
  name TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0)""",
]

class DB:
    def __init__(self):
        url = os.environ.get("DATABASE_URL", "")
        self.kind = "neon" if url.startswith("postgres") else "sqlite"
        if self.kind == "sqlite":
            path = url.replace("sqlite:///", "") or os.path.join(os.path.dirname(__file__), "catalogiq-local.db")
            self.conn = sqlite3.connect(path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        else:
            self.url = url

    # --- neon https backend -------------------------------------------------
    def _neon(self, sql, params):
        # Neon serverless HTTP: POST https://<host>/sql
        # headers: Neon-Connection-String, Content-Type: application/json
        from urllib.parse import urlparse
        u = urlparse(self.url)
        endpoint = f"https://{u.hostname}/sql"
        body = json.dumps({"query": sql, "params": params}).encode()
        req = urllib.request.Request(endpoint, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Neon-Connection-String", self.url)
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
        cols = [f["name"] for f in data.get("fields", [])]
        return [dict(zip(cols, row)) for row in data.get("rows", [])]

    # --- unified interface --------------------------------------------------
    def q(self, sql, params=()):
        if self.kind == "sqlite":
            cur = self.conn.execute(sql.replace("%s", "?"), params)
            return [dict(r) for r in cur.fetchall()]
        return self._neon(sql, list(params))

    def one(self, sql, params=()):
        rows = self.q(sql, params)
        return rows[0] if rows else None

    def exec(self, sql, params=()):
        if self.kind == "sqlite":
            cur = self.conn.execute(sql.replace("%s", "?"), params)
            self.conn.commit()
            return cur.lastrowid
        self._neon(sql, list(params))
        return None

    def next_seq(self, name):
        row = self.one("SELECT value FROM counters WHERE name=%s", (name,))
        if row is None:
            self.exec("INSERT INTO counters(name, value) VALUES(%s, 1)", (name,))
            return 1
        v = int(row["value"]) + 1
        self.exec("UPDATE counters SET value=%s WHERE name=%s", (v, name))
        return v

    def init_schema(self):
        for stmt in SCHEMA:
            if self.kind == "sqlite":
                self.conn.execute(stmt.replace("AUTOINCREMENT", "AUTOINCREMENT"))
                self.conn.commit()
            else:
                self._neon(stmt.replace("INTEGER PRIMARY KEY AUTOINCREMENT",
                                        "SERIAL PRIMARY KEY"), [])
