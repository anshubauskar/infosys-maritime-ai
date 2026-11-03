"""Web server: FastAPI JSON API + server-sent events + the single-page front end. Models live on the GPU in this process; the simulator and agent cycles run in worker.py."""
import sqlite3, os, sys, io, re, csv, json, time, asyncio
import subprocess, threading, importlib, datetime, secrets
import jwt
import bcrypt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from config import KIND, DB_PATH
from fastapi import FastAPI, Request, Response, HTTPException, UploadFile, File, Form, Header
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import pandas as pd
import numpy as np
import gpu, qa as QA, analyst as AN, live_engine as LE, entities as EN, blocks as B
import views_core as VC
dom = importlib.import_module("domain_franchise" if KIND == "Franchise" else "domain_freight")
V = importlib.import_module("views_franchise" if KIND == "Franchise" else "views_freight")
HERE = os.path.dirname(os.path.abspath(__file__)); STATIC = os.path.join(HERE, "static")
app = FastAPI(title=f"{V.NAME} Platform", docs_url=None, redoc_url=None, openapi_url=None) if os.environ.get("PUBLIC_DOCS") != "1" else FastAPI(title=f"{V.NAME} Platform"); _worker = None; _ready = {"db": False}
import hardening; hardening.install(app, KIND)

@app.middleware("http")
async def sec(request, call_next):
    r = await call_next(request); r.headers["X-Content-Type-Options"] = "nosniff"; r.headers["Referrer-Policy"] = "same-origin"; r.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api") else r.headers.get("Cache-Control", "public, max-age=300"); return r

def _boot():
    from db import init_db; from seed_data import seed_all
    init_db(); seed_all(); LE.init_live_tables(); _ready["db"] = True
@app.on_event("startup")
def startup():
    global _worker
    _boot()
    if os.environ.get("NO_WORKER") != "1":
        env = {**os.environ, "APP_KIND": KIND}; _worker = subprocess.Popen([sys.executable, os.path.join(HERE, "worker.py")], env=env, cwd=HERE)
@app.on_event("shutdown")
def shutdown():
    if _worker:
        try: _worker.terminate()
        except Exception: pass

# ------------------------------------------------------------------ auth + context
# ------------------------------------------------------------------
# AUTHENTICATION + CONTEXT
# ------------------------------------------------------------------

JWT_SECRET = config.JWT_SECRET_KEY

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not configured.")

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 2


def create_access_token(user):
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "exp": datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(hours=JWT_EXPIRY_HOURS)
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def get_user_by_id(user_id):
    from db import get_conn

    conn = get_conn()
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row

    row = cursor.execute(
        """
        SELECT id, username, email, password_hash, role,
               failed_attempts, lock_until, account_status, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    return dict(row) if row else None



def user_of(request: Request):
    authorization = request.headers.get("Authorization", "")

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )

    user = get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User account not found"
        )

    if user["account_status"] == "locked":
        if user["lock_until"]:
            try:
                lock_time = datetime.datetime.fromisoformat(
                    str(user["lock_until"])
                )

                if lock_time.tzinfo is None:
                    lock_time = lock_time.replace(
                        tzinfo=datetime.timezone.utc
                    )

                now = datetime.datetime.now(datetime.timezone.utc)

                if lock_time > now:
                    raise HTTPException(
                        status_code=403,
                        detail="Account is temporarily locked"
                    )

                # Lock period has expired.
                # Account reactivation must be handled in the database.

            except ValueError:
                raise HTTPException(
                    status_code=403,
                    detail="Invalid account lock information"
                )

        else:
            raise HTTPException(
                status_code=403,
                detail="Account is locked. Contact administrator."
            )

    elif user["account_status"] != "active":
        raise HTTPException(
            status_code=403,
            detail="Account is inactive"
        )

    return user



def ctx(u, params=None):
    return {
        "dom": dom,
        "kind": KIND,
        "role": u["role"],
        "email": u["email"],
        "user": u,
        "scope": None,
        "params": params or {}
    }


def need(c, cap):
    return None


def menu_for(role):
    return list(V.MENU)
def ok(msg="Done", **kw): return {"ok": True, "msg": msg, **kw}
def bad(msg): return JSONResponse({"ok": False, "msg": msg}, status_code=400)

# ------------------------------------------------------------------
# Task A: Authentication endpoints
# ------------------------------------------------------------------

import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage

from db import get_conn

# Temporary OTP storage: OTPs expire after 5 minutes.
# This is suitable for the current single-process Colab milestone demo.
OTP_STORE = {}

def valid_auth_email(email):
    # At least 2 characters before @, 2 between @ and dot,
    # and 2 after the final dot.
    return bool(re.fullmatch(
        r"[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\.[A-Za-z]{2,}",
        email
    ))

def valid_auth_password(password):
    return (
        isinstance(password, str)
        and len(password) >= 8
        and not any(ch.isspace() for ch in password)
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[^A-Za-z0-9\s]", password)
    )

def find_auth_user(email):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row

    row = cursor.execute(
        """
        SELECT id, username, email, password_hash, role,
               failed_attempts, lock_until, account_status, created_at
        FROM users
        WHERE email = ?
        """,
        (email,)
    ).fetchone()

    return dict(row) if row else None

def send_reset_otp(email, otp):
    sender = config.EMAIL_ID
    password = config.EMAIL_PASSWORD

    if not sender or not password:
        raise RuntimeError(
            "Email is not configured. Set EMAIL_ADDRESS and EMAIL_PASSWORD."
        )

    message = EmailMessage()
    message["Subject"] = "FreightQuote AI - Password Reset OTP"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your password reset OTP is {otp}.\n"
        "This OTP expires in 5 minutes. Do not share it with anyone."
    )

    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465,
        context=ssl.create_default_context(),
        timeout=20
    ) as smtp:
        smtp.login(sender, password)
        smtp.send_message(message)


# 1. SIGNUP
@app.post("/api/auth/signup")
async def auth_signup(request: Request):
    data = await request.json()

    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")

    if not username:
        return bad("Username is required.")

    if not valid_auth_email(email):
        return bad("Enter a valid email address.")

    if not valid_auth_password(password):
        return bad(
            "Password must contain at least 8 characters, "
            "uppercase, lowercase, a number and a special character. "
            "Spaces are not allowed."
        )

    if password != confirm_password:
        return bad("Passwords do not match.")

    if len(password.encode("utf-8")) > 72:
        return bad("Password is too long.")

    conn = get_conn()

    try:
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cursor = conn.execute(
            """INSERT INTO users
               (username, email, password_hash, role,
                failed_attempts, account_status)
               VALUES (?, ?, ?, ?, 0, 'active')""",
            (username, email, password_hash, "user")
        )
        conn.commit()

        user = find_auth_user(email)
        token = create_access_token(user)

        return {
            "ok": True,
            "msg": "Account created successfully.",
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"]
            }
        }

    except sqlite3.IntegrityError:
        conn.rollback()
        return bad("Username or email is already registered.")


# 2. LOGIN
@app.post("/api/auth/login")
async def auth_login(request: Request):
    data = await request.json()

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    user = find_auth_user(email)
    invalid_message = "Invalid email or password."

    if not user:
        return JSONResponse(
            {"ok": False, "msg": invalid_message},
            status_code=401
        )

    conn = get_conn()

    # Check whether the account is temporarily locked.
    if user["account_status"] == "locked":

        if not user["lock_until"]:
            return JSONResponse(
                {"ok": False, "msg": "Account is locked. Contact the administrator."},
                status_code=403
            )

        try:
            lock_time = datetime.datetime.fromisoformat(
                str(user["lock_until"])
            )

            if lock_time.tzinfo is None:
                lock_time = lock_time.replace(
                    tzinfo=datetime.timezone.utc
                )

            now = datetime.datetime.now(datetime.timezone.utc)

            if lock_time > now:
                return JSONResponse(
                    {"ok": False, "msg": "Account is locked. Please try again after five minutes."},
                    status_code=403
                )

            # Five-minute lock period has expired.
            conn.execute(
                """UPDATE users
                   SET failed_attempts = 0,
                       account_status = 'active',
                       lock_until = NULL
                   WHERE id = ?""",
                (user["id"],)
            )
            conn.commit()

            user = find_auth_user(email)

        except ValueError:
            return JSONResponse(
                {"ok": False, "msg": "Invalid account lock information."},
                status_code=403
            )

    elif user["account_status"] != "active":
        return JSONResponse(
            {"ok": False, "msg": "Account is inactive. Contact the administrator."},
            status_code=403
        )

    if not user["password_hash"]:
        return JSONResponse(
            {"ok": False, "msg": invalid_message},
            status_code=401
        )

    password_ok = bcrypt.checkpw(
        password.encode("utf-8"),
        user["password_hash"].encode("utf-8")
    )

    if not password_ok:
        attempts = int(user["failed_attempts"] or 0) + 1

        if attempts >= 5:
            lock_until = (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(minutes=5)
            ).isoformat()

            conn.execute(
                """UPDATE users
                   SET failed_attempts = ?,
                       account_status = 'locked',
                       lock_until = ?
                   WHERE id = ?""",
                (attempts, lock_until, user["id"])
            )
            conn.commit()

            return JSONResponse(
                {"ok": False, "msg": "Account locked after 5 failed login attempts. Try again after five minutes."},
                status_code=403
            )

        conn.execute(
            "UPDATE users SET failed_attempts = ? WHERE id = ?",
            (attempts, user["id"])
        )
        conn.commit()

        return JSONResponse(
            {"ok": False, "msg": invalid_message},
            status_code=401
        )

    # Successful login: clear failed attempts and lock information.
    conn.execute(
        """UPDATE users
           SET failed_attempts = 0,
               account_status = 'active',
               lock_until = NULL
           WHERE id = ?""",
        (user["id"],)
    )
    conn.commit()

    token = create_access_token(user)

    return {
        "ok": True,
        "msg": "Login successful.",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
    }



# 3. FORGOT PASSWORD - SEND OTP
@app.post("/api/auth/forgot")
async def auth_forgot(request: Request):
    data = await request.json()
    email = str(data.get("email", "")).strip().lower()

    if not valid_auth_email(email):
        return bad("Enter a valid email address.")

    user = find_auth_user(email)

    # Do not disclose whether an email is registered.
    generic_message = (
        "If the account exists, a password reset OTP has been sent."
    )

    if not user:
        return {"ok": True, "msg": generic_message}

    if user["account_status"] != "active":
        return {"ok": True, "msg": generic_message}

    otp = f"{secrets.randbelow(1000000):06d}"

    try:
        send_reset_otp(email, otp)
    except Exception as e:
        print("OTP email error:", repr(e))
        return JSONResponse(
            {"ok": False, "msg": "Could not send OTP. Check email configuration."},
            status_code=500
        )

    OTP_STORE[email] = {
        "otp": otp,
        "expires_at": (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=5)
        )
    }

    return {"ok": True, "msg": generic_message}


# 4. RESET PASSWORD - VERIFY OTP AND UPDATE PASSWORD
@app.post("/api/auth/reset")
async def auth_reset(request: Request):
    data = await request.json()

    email = str(data.get("email", "")).strip().lower()
    otp = str(data.get("otp", "")).strip()
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not valid_auth_email(email):
        return bad("Enter a valid email address.")

    if not re.fullmatch(r"\d{6}", otp):
        return bad("Enter the 6-digit OTP.")

    if not valid_auth_password(new_password):
        return bad(
            "Password must contain at least 8 characters, "
            "uppercase, lowercase, a number and a special character. "
            "Spaces are not allowed."
        )

    if new_password != confirm_password:
        return bad("Passwords do not match.")

    if len(new_password.encode("utf-8")) > 72:
        return bad("Password is too long.")

    saved_otp = OTP_STORE.get(email)

    if not saved_otp:
        return bad("OTP is invalid or expired. Request a new OTP.")

    now = datetime.datetime.now(datetime.timezone.utc)

    if now >= saved_otp["expires_at"]:
        OTP_STORE.pop(email, None)
        return bad("OTP is invalid or expired. Request a new OTP.")

    if not secrets.compare_digest(otp, saved_otp["otp"]):
        return bad("Incorrect OTP.")

    user = find_auth_user(email)

    if not user:
        OTP_STORE.pop(email, None)
        return bad("Unable to reset password for this account.")

    password_hash = bcrypt.hashpw(
        new_password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    conn = get_conn()
    conn.execute(
        """UPDATE users
           SET password_hash = ?,
               failed_attempts = 0,
               account_status = 'active',
               lock_until = NULL
           WHERE id = ?""",
        (password_hash, user["id"])
    )
    conn.commit()

    # OTP can only be used once.
    OTP_STORE.pop(email, None)

    return {"ok": True, "msg": "Password reset successfully. You can now log in."}

@app.get("/api/public")
def public():
    s = LE.get_state("boot", {}) if _ready["db"] else {}
    return {"kind": KIND, "name": V.NAME, "stage": (s or {}).get("stage", "starting"), "gpu": {"cuda": False, "name": None}, "questions": [], "email_enabled": False, "demo": []}
@app.get("/api/me")
def me(request: Request):
    user = user_of(request)

    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        },
        "kind": KIND,
        "name": V.NAME,
        "menu": [
            {"id": i, "label": label, "icon": icon}
            for i, label, icon in V.MENU
        ],
        "caps": [],
        "scope": None,
        "langs": ["English"],
        "questions": []
    }
# ------------------------------------------------------------------ live pulse
def pulse():
    rt = LE.get_state("runtime", {}) or {}; boot = LE.get_state("boot", {}) or {}; d = VC.decision()
    oa = B.Q("SELECT status, severity, COUNT(*) n FROM agent_actions WHERE status IN ('open','proposed') GROUP BY status, severity")
    n = lambda st, sv=None: int(oa[(oa.status == st) & ((oa.severity == sv) if sv else True)].n.sum()) if len(oa) else 0
    return {"stage": boot.get("stage", "starting"), "ticks": rt.get("ticks", 0), "cycles": rt.get("cycles", 0), "last_cycle": rt.get("last_cycle"), "health": d["score"] if d else None, "risk": d["risk"] if d else None, "dec": d["id"] if d else 0,
            "open": n("open"), "critical": n("open", "Critical"), "proposed": 0, "gpu": {"cuda": True, "name": "", "used": 0, "total": 0, "llm": "off", "llm_name": "", "llm_done": 0, "llm_total": 0}, "worker_alive": bool(rt.get("last_cycle"))}
@app.get("/api/pulse")
def pulse_http(request: Request): user_of(request); return pulse()
@app.get("/api/stream")
async def stream(request: Request):
    user_of(request)
    async def gen():
        last = None; t0 = time.time()
        while True:
            if await request.is_disconnected(): break
            try: p = await asyncio.to_thread(pulse)
            except Exception as e: p = {"error": str(e)}
            k = json.dumps(p, sort_keys=True, default=str)
            if k != last or time.time() - t0 > 10: last = k; t0 = time.time(); yield f"data: {k}\n\n"
            await asyncio.sleep(1.5)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ------------------------------------------------------------------ pages
_TABS = {}
def _tabs_of(c, f):
    if f not in _TABS: _TABS[f] = f(c, None).get("tabs")
    return _TABS[f]
def _page(c, pid, tab):
    if pid == "copilot": return B.page("AI Copilot", "Ask about your data in plain English. Answers are exact database queries.", [{"t": "chat", "examples": EXAMPLES, "langs": ["English"]}], [], live=0)
    f = V.PAGES.get(pid)
    if not f: raise HTTPException(404, "unknown page")
    o = f(c, tab); _TABS[f] = o.get("tabs"); return o
@app.get("/api/page/{pid}")
def page(pid: str, request: Request, tab: str = "", p: str = ""):
    u = user_of(request); c = ctx(u, json.loads(p) if p else {})
    t = time.time(); out = _page(c, pid, tab or None); out["id"] = pid; out["ms"] = round((time.time() - t) * 1000); return JSONResponse(B.clean(out))
@app.get("/api/detail/{eid:path}")
def detail(eid: str, request: Request):
    u = user_of(request); c = ctx(u)
    return JSONResponse(B.clean(V.detail(c, eid)))

# ------------------------------------------------------------------ tickets, cycles, policy
@app.post("/api/run_cycle")
def run_cycle(request: Request):
    u = user_of(request); c = ctx(u); need(c, "run"); t = time.time(); LE.run_cycle(dom, "manual", ""); LE.audit(u["email"], "manual_cycle", "all"); return ok(f"Agents finished in {time.time() - t:.1f}s")
@app.post("/api/run_agent")
async def run_agent(request: Request):
    u = user_of(request); c = ctx(u); need(c, "run"); a = (await request.json()).get("agent")
    if a not in dom.AGENTS: raise HTTPException(404, "unknown agent")
    await asyncio.to_thread(_run_one, a); LE.audit(u["email"], "manual_agent", a); return ok(f"{a} re-ran")
def _run_one(agent):
    cid = time.strftime("%m%d-%H%M%S") + "-page"; t = time.time(); s = {"cycle_id": cid, "trigger": "page", "request": "", "queue": [], "results": {}}
    if agent == "digest":
        for a in ("outlet", "inventory", "staff", "marketing", "audit"): s["results"][a] = dom.AGENTS[a](s)
    res = dom.AGENTS[agent](s); LE._log_run(cid, "page", res, int((time.time() - t) * 1000)); s["results"][agent] = res; LE.act(dom, {"actions": res.actions}, cid, {agent: res})

# ------------------------------------------------------------------ admin users

# ------------------------------------------------------------------ digital twin

# ------------------------------------------------------------------ data feeds

# ------------------------------------------------------------------ Franchise actions
@app.post("/api/franchise/review")
async def fr_review(request: Request):
    import uuid; u = user_of(request); c = ctx(u); d = await request.json(); tx = str(d.get("comment", "")).strip()
    if not tx: return bad("Write a comment first")
    src = "eng_Latn"; en = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+|\+?\d[\d -]{8,}\d", "[removed]", tx)
    try: from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer; sc = SentimentIntensityAnalyzer().polarity_scores(en)["compound"]
    except Exception: sc = (int(d["rating"]) - 3) / 2
    rt = int(d["rating"])
    with LE._DB_LOCK, LE.conn() as cn: cn.execute("INSERT INTO feedback(feedback_id,outlet_id,rating,comment,date,sentiment_score) VALUES(?,?,?,?,?,?)", ("FB-U" + uuid.uuid4().hex[:10], d["outlet"], rt, en, datetime.date.today().isoformat(), .6 * (rt - 3) / 2 + .4 * sc))
    LE.emit("review", d["outlet"], {"rating": rt}); return ok(f"Stored for {d['outlet']} (sentiment {sc:+.2f}{', translated from ' + src if src != 'eng_Latn' else ''}). The Sentiment agent includes it in its next cycle.", refresh=True)
@app.post("/api/franchise/audit")
async def fr_audit(request: Request):
    import uuid; u = user_of(request); c = ctx(u); need(c, "resolve"); d = await request.json(); sc = int(d["score"])
    with LE._DB_LOCK, LE.conn() as cn: cn.execute("INSERT INTO audits(audit_id,outlet_id,audit_date,score,violations,category,status,notes) VALUES(?,?,?,?,?,?,?,?)", ("AUD-U" + uuid.uuid4().hex[:10], d["outlet"], datetime.date.today().isoformat(), sc, int((100 - sc) / 6), d["category"], "Pass" if sc >= 80 else "Warning" if sc >= 60 else "Fail", d.get("notes", "")))
    LE.emit("audit", d["outlet"], {"score": sc}); LE.audit(u["email"], "audit_logged", d["outlet"], str(sc)); await asyncio.to_thread(_run_one, "audit"); return ok("Saved and evaluated by the Audit agent.", refresh=True)

# ------------------------------------------------------------------ Freight actions
@app.post("/api/freight/quote")
async def fq_quote(request: Request):
    u = user_of(request); c = ctx(u); need(c, "quote"); d = await request.json()
    if u["role"] == "Customer":
        if not u.get("customer_id"): raise HTTPException(403, "Your account is not linked to a customer record.")
        d["customer"] = u["customer_id"]  # Never trust a customer_id supplied by the browser.
    if d["o"] == d["d"]: return bad("Origin and destination must differ.")
    rid = dom.submit_request(d["o"], d["d"], d["cargo"], float(d["weight"]), d["hs"], d["customer"], "English", d.get("docs") or []); await asyncio.to_thread(dom.run_quote, rid); LE.audit(u["email"], "quote_created", str(rid), f"{d['o']}->{d['d']}")
    return ok("Quote generated", blocks=B.clean(V.quote_result(rid)))
@app.post("/api/freight/storm")
async def fq_storm(request: Request):
    PRESET_STORMS = {"Red Sea": (18.0, 40.0), "Arabian Sea": (16.0, 66.0), "Bay of Bengal": (14.0, 88.0), "South China Sea": (14.0, 114.0), "Mediterranean": (35.0, 18.0)}; u = user_of(request); c = ctx(u); need(c, "admin"); d = await request.json() if request.headers.get("content-length", "0") not in ("0", "2") else {}
    la, lo = PRESET_STORMS.get(d.get("area") or "Red Sea"); dom.inject_storm(la, lo, wind=float(d.get("wind", 24))); LE.audit(u["email"], "inject_storm", d.get("area", "Red Sea")); return ok("Storm injected. The weather agent will propose re-routes on its next cycle.", refresh=True)
@app.post("/api/freight/reroute")
async def fq_reroute(request: Request):
    u = user_of(request); c = ctx(u); need(c, "approve"); j = await request.json(); sid = j["shipment"]; opt = j.get("opt")
    idx = int(str(opt).split(".")[0]) - 1 if opt else None; act = {"type": "reroute", "target": sid}
    if idx is not None: act["opt_label"] = str(opt).split(" · ", 1)[-1]; act["opt_idx"] = idx
    with LE._DB_LOCK, LE.conn() as cn: note = dom.apply(act, cn)
    LE.audit(u["email"], "manual_reroute", sid, note); return ok(note or "no change", refresh=True)
@app.post("/api/freight/attach")
async def fq_attach(request: Request):
    u = user_of(request); c = ctx(u)
    d = await request.json(); dom.attach_doc(d["ref"], d["doc"], u["email"]); LE.audit(u["email"], "doc_attached", d["ref"], d["doc"]); return ok("Attached. Quotes re-run immediately; shipments clear on the next customs cycle.", refresh=True)
@app.post("/api/freight/readdoc")
async def fq_readdoc(request: Request, file: UploadFile = File(...)):
    u = user_of(request); data = await file.read(); txt = ""
    try:
        if file.filename.lower().endswith(".pdf"):
            import pdfplumber
            with pdfplumber.open(io.BytesIO(data)) as pdf: txt = "\n".join((pg.extract_text() or "") for pg in pdf.pages)
        else: txt = data.decode("utf-8", errors="ignore")
    except Exception as e: return bad(f"Could not read the file: {e}")
    hs = re.findall(r"HS[- ]?\d{2,8}", txt); q = re.findall(r"QTE-L\d+", txt); wt = re.findall(r"(\d+(?:\.\d+)?)\s*(?:t|tons|kg)\b", txt)
    return ok("Read", blocks=[B.table([{"field": "HS code", "value": ", ".join(dict.fromkeys(hs)) or "-"}, {"field": "Quote reference", "value": ", ".join(dict.fromkeys(q)) or "-"}, {"field": "Weights", "value": ", ".join(wt[:3]) or "-"}], ["field", "value"], title="Fields found", h=170, key="ocr"), B.md("```\n" + txt[:2500] + "\n```")])

# ------------------------------------------------------------------ language, knowledge base

# ------------------------------------------------------------------ Copilot (agents first, then the GPU LLM; NLLB for every language) + executive brief
def _sse(ev, **kw): return f"data: {json.dumps({'ev': ev, **kw}, default=str)}\n\n"
SYSTEM = "You are the operations copilot of an agentic platform. Answer ONLY from the EVIDENCE. Quote numbers exactly as given, never invent any. Be concise: a one-line answer, then up to 5 short bullets with the entity ids. If the evidence does not answer, say so. When you use a numbered source, cite it as [1], [2]."
_BRIEF = {}
def _chat_db():
    c = sqlite3.connect(DB_PATH, timeout=30); c.execute("PRAGMA journal_mode=WAL;"); c.execute("CREATE TABLE IF NOT EXISTS copilot_chats(id TEXT PRIMARY KEY, email TEXT, title TEXT, ts TEXT, data TEXT)"); c.execute("CREATE INDEX IF NOT EXISTS ix_chat_email ON copilot_chats(email, ts)"); return c
@app.get("/api/chats")
async def chats_list(request: Request):
    u = user_of(request)
    with _chat_db() as c: rows = c.execute("SELECT id, title, ts FROM copilot_chats WHERE email=? ORDER BY ts DESC LIMIT 60", (u["email"],)).fetchall()
    return {"ok": True, "chats": [{"id": r[0], "title": r[1], "ts": r[2]} for r in rows]}
@app.get("/api/chats/{cid}")
async def chats_get(cid: str, request: Request):
    u = user_of(request)
    with _chat_db() as c: r = c.execute("SELECT title, data FROM copilot_chats WHERE id=? AND email=?", (cid, u["email"])).fetchone()
    if not r: raise HTTPException(404, "chat not found")
    return {"ok": True, "title": r[0], "msgs": json.loads(r[1])}
@app.post("/api/chats/save")
async def chats_save(request: Request):
    u = user_of(request); d = await request.json(); cid = re.sub(r"[^a-zA-Z0-9_-]", "", str(d.get("id") or ""))[:40] or ("c" + str(int(time.time() * 1000))); msgs = d.get("msgs") or []
    if not isinstance(msgs, list) or not msgs: return bad("nothing to save")
    msgs = [{"role": m.get("role"), "text": str(m.get("text", ""))[:20000], "en": (str(m["en"])[:20000] if m.get("en") else None), "lang": m.get("lang"), "sql": str(m.get("sql") or "")[:1500]} for m in msgs[-80:]]
    title = next((m["text"] for m in msgs if m["role"] == "user"), "Chat")[:70]; now = datetime.datetime.now().isoformat(timespec="seconds")
    with _chat_db() as c:
        o = c.execute("SELECT email FROM copilot_chats WHERE id=?", (cid,)).fetchone()
        if o and o[0] != u["email"]: raise HTTPException(403, "not your chat")
        c.execute("INSERT OR REPLACE INTO copilot_chats VALUES(?,?,?,?,?)", (cid, u["email"], title, now, json.dumps(msgs)))
    return {"ok": True, "id": cid}
@app.delete("/api/chats/{cid}")
async def chats_del(cid: str, request: Request):
    u = user_of(request)
    with _chat_db() as c: c.execute("DELETE FROM copilot_chats WHERE id=? AND email=?", (cid, u["email"]))
    return {"ok": True}
@app.post("/api/weather/refresh")
async def wx_refresh(request: Request):
    u = user_of(request); c = ctx(u); need(c, "run")
    if KIND != "Freight": raise HTTPException(404)
    import weather as WX; n, msg = await asyncio.to_thread(WX.refresh); LE.audit(u["email"], "weather_refresh", "ports", msg)
    return ok(("Real weather updated: " if n else "Could not reach Open-Meteo, simulated values stay: ") + msg, refresh=True)

# ------------------------------------------------------------------ reports, exports, profile, invitations


@app.get("/api/health")
def health(): return {"ok": True, "gpu": gpu.status()}
@app.get("/")
def index(): return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-store"})
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ------------------------------------------------------------------ AI Copilot (SQL only: greetings + exact database answers)
EXAMPLES = ["Which port has the highest congestion?", "How many shipments are delayed?", "Which quotes have a low margin?", "Which shipments are on customs hold?", "Which carrier is least reliable?"]
GREET = re.compile(r"^\W*(hi|hello|hey|hii|good (morning|afternoon|evening)|namaste|yo)\b[\w\s!.,]*$", re.I)
THANKS = re.compile(r"^\W*(thanks|thank you|thx|ok thanks|great|cool)\b[\w\s!.,]*$", re.I)
@app.post("/api/copilot")
async def copilot(request: Request):
    u = user_of(request)

    d = await request.json()
    q = str(d.get("q", "")).strip()[:800]
    def gen():
        t0 = time.time()
        if GREET.match(q): yield _sse("final", text="Hello! I answer questions about your live data with exact database queries. Try one of the examples below.", sql="", ms=0); yield _sse("done"); return
        if THANKS.match(q): yield _sse("final", text="You're welcome! Ask me anything else about your data.", sql="", ms=0); yield _sse("done"); return
        exact = None
        try: exact = AN.answer(KIND, q, None, VC.decision(), dom) or QA.answer(KIND, q, None, None)
        except Exception as e: print("copilot failed:", repr(e), file=sys.stderr)
        if exact and exact.get("answer"):
            tbl = (QA.md(exact["df"]) if exact.get("df") is not None else "") + (("\n\n" + exact["extra"]) if exact.get("extra") else "")
            yield _sse("exact", sql=exact["sql"], rows=0 if exact["df"] is None else len(exact["df"]))
            final = exact["answer"] + (("\n\n" + tbl) if tbl else ""); yield _sse("final", text=final, sql=exact.get("sql", ""), ms=round((time.time() - t0) * 1000))
        else: yield _sse("final", text="I could not compute an exact answer to that from the tables. Try one of these:\n" + "\n".join("- " + e for e in EXAMPLES), sql="", ms=round((time.time() - t0) * 1000))
        yield _sse("done")
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# Milestone 2 Task D: server-side RBAC, profile and admin APIs.
import milestone2_patch
milestone2_patch.install(app)
