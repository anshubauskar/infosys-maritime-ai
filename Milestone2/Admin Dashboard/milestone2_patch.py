"""
FastAPI integration layer for FreightQuote AI Milestone 2.
Adds server-side RBAC, profile endpoints, and an Admin API.
This is a Colab milestone/demo implementation, not a hardened public production deployment.
"""
import os, re, time, sqlite3, secrets, datetime, threading
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
import bcrypt
from rbac import ROLES, ADMIN, OPS, BROKER, AUDITOR, CUSTOMER, can_page, can_do, menu_for as _menu

ROLES = ("Admin", "Operations Manager", "Freight Broker", "Auditor", "Customer")
ADMIN, OPS, BROKER, AUDITOR, CUSTOMER = ROLES
ROLE_MENU = {
    ADMIN: {"copilot","route","quotes","carriers","weather","margin","customs","admin","profile"},
    OPS: {"copilot","route","carriers","weather","customs","profile"},
    BROKER: {"copilot","quotes","carriers","margin","profile"},
    AUDITOR: {"copilot","route","quotes","carriers","weather","margin","customs","profile"},
    CUSTOMER: {"copilot","quotes","profile"},
}
ROLE_CAPS = {
    ADMIN: {"users","quote","run","approve","resolve","admin","storm"},
    OPS: {"run","approve","resolve"},
    BROKER: {"quote"},
    AUDITOR: set(),
    CUSTOMER: {"quote_own"},
}
MENU_LABELS = {
    "copilot": ("AI Copilot","bot"), "route": ("Agent 1 · Route AI","route"),
    "quotes": ("Agent 2 · Spot Quotes","dollar"), "carriers": ("Agent 3 · Carriers","truck"),
    "weather": ("Agent 4 · Weather Risk","cloud"), "margin": ("Agent 5 · Margin","trend"),
    "customs": ("Agent 6 · Customs","file"), "admin": ("Admin dashboard","users"),
    "profile": ("My profile","user"),
}
_LOCK = threading.RLock()

def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()

def _conn(s):
    from db import get_conn
    return get_conn()

def _ensure_schema(s):
    c = _conn(s)
    c.execute("PRAGMA foreign_keys=ON")
    existing = {r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()}
    migrations = {
        "username": "ALTER TABLE users ADD COLUMN username TEXT",
        "customer_id": "ALTER TABLE users ADD COLUMN customer_id TEXT",
        "last_login": "ALTER TABLE users ADD COLUMN last_login TEXT",
        "failed_attempts": "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0",
        "lock_until": "ALTER TABLE users ADD COLUMN lock_until TEXT",
        "account_status": "ALTER TABLE users ADD COLUMN account_status TEXT DEFAULT 'active'",
    }
    for col, ddl in migrations.items():
        if col not in existing:
            c.execute(ddl)
    c.execute("""CREATE TABLE IF NOT EXISTS activity_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
        action TEXT NOT NULL, target TEXT DEFAULT '', detail TEXT DEFAULT '')""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity_log(id DESC)")
    # Remove only known insecure demo records created by the supplied seed_data.py.
    c.execute("DELETE FROM users WHERE password_hash='admin123' AND email IN ('admin@infosys.com','broker@infosys.com','customer@infosys.com')")
    # Ensure a first administrator exists. The password comes from config/Colab Secret,
    # never from a literal demo password in source code.
    n = c.execute("SELECT COUNT(*) FROM users WHERE role='Admin' AND account_status='active'").fetchone()[0]
    if not n:
        import config
        email = (getattr(config, "ADMIN_EMAIL_ID", "") or "").strip().lower()
        password = getattr(config, "ADMIN_PASSWORD", "") or ""
        if not email or not password:
            raise RuntimeError("Set ADMIN_EMAIL_ID and ADMIN_PASSWORD in Colab Secrets before first run.")
        if not re.fullmatch(r"[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\.[A-Za-z]{2,}", email):
            raise RuntimeError("ADMIN_EMAIL_ID is not a valid email address.")
        ph = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        found = c.execute("SELECT id FROM users WHERE lower(email)=lower(?)", (email,)).fetchone()
        if found:
            c.execute("UPDATE users SET password_hash=?, role='Admin', account_status='active', failed_attempts=0, lock_until=NULL WHERE id=?", (ph, found[0]))
        else:
            c.execute("INSERT INTO users(username,email,password_hash,role,failed_attempts,account_status,created_at) VALUES(?,?,?,?,0,'active',?)",
                      ("Administrator", email, ph, ADMIN, _now()))
    c.commit()

def can_page(role, page):
    return page == "profile" and role in ROLES or page in ROLE_MENU.get(role, set())

def can_do(role, capability):
    if role == ADMIN: return True
    aliases = {
        "users": "users", "quote": "quote", "run": "run", "approve": "approve",
        "resolve": "resolve", "admin": "admin", "storm": "storm", "view": "view"
    }
    if capability == "view": return role in ROLES
    if role == CUSTOMER and capability == "quote": return False
    return aliases.get(capability, capability) in ROLE_CAPS.get(role, set())

def _menu(role):
    # Preserve the canonical order used by the supplied FreightQuote UI.
    order = ["copilot","route","quotes","carriers","weather","margin","customs","admin","profile"]
    return [{"id": p, "label": MENU_LABELS[p][0], "icon": MENU_LABELS[p][1]}
            for p in order if can_page(role,p)]

def _log(c, actor, action, target="", detail=""):
    c.execute("INSERT INTO activity_log(ts,actor,action,target,detail) VALUES(?,?,?,?,?)",
              (_now(), actor, action, str(target)[:160], str(detail)[:500]))

def _password_ok(p):
    return (isinstance(p,str) and 8 <= len(p) <= 64 and not any(x.isspace() for x in p)
            and bool(re.search(r"[A-Z]",p)) and bool(re.search(r"[a-z]",p))
            and bool(re.search(r"\d",p)) and bool(re.search(r"[^A-Za-z0-9\s]",p)))

def _public_user(row):
    keys = ("id","username","email","role","account_status","created_at","last_login","customer_id")
    return {k: row[k] for k in keys if k in row.keys()}

def install(app):
    import server as s
    # Schema and first-admin bootstrap run in a startup hook after the base DB init.

    # Apply tighter limits to the actual /api/auth/* routes used by this notebook.
    try:
        import hardening
        hardening.LIMITS.update({
            "/api/auth/login": (10, 60),
            "/api/auth/signup": (6, 600),
            "/api/auth/forgot": (5, 300),
            "/api/auth/reset": (8, 600),
        })
    except Exception:
        pass

    # Replace the no-op authorization helpers in the supplied server.
    def need(c, cap):
        role = (c or {}).get("role")
        if cap == "quote" and role == CUSTOMER and (c or {}).get("customer_id"):
            return True
        if not can_do(role, cap):
            raise HTTPException(status_code=403, detail=f"403 - the {role or 'unknown'} role cannot perform '{cap}'.")
        return True
    def menu_for(role):
        return _menu(role)
    s.need = need
    s.menu_for = menu_for

    # Make page builders' capability checks respect roles too.
    try:
        import views_core as VC
        VC.can = lambda c, cap: (
            cap == "quote" and (c or {}).get("role") == CUSTOMER and bool((c or {}).get("customer_id"))
        ) or can_do((c or {}).get("role"), cap)
        if hasattr(s, "V"): s.V.can = VC.can
        # Existing views use "quote" to show the create form and "view" to show read-only data.
    except Exception:
        pass

    # Attach customer identity to request context.
    old_ctx = s.ctx
    def ctx(u, params=None):
        out = old_ctx(u, params)
        out["customer_id"] = u.get("customer_id")
        return out
    s.ctx = ctx

    def get_user_by_id(user_id):
        c = _conn(s)
        row = c.execute("""SELECT id,username,email,password_hash,role,failed_attempts,
            lock_until,account_status,created_at,last_login,customer_id FROM users WHERE id=?""",
            (user_id,)).fetchone()
        return dict(row) if row else None
    s.get_user_by_id = get_user_by_id

    # Patch the page router to fail closed for direct URL access.
    @app.middleware("http")
    async def milestone2_page_guard(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/page/"):
            try:
                user = s.user_of(request)
                pid = path.rsplit("/",1)[-1]
                if not can_page(user.get("role"), pid):
                    return JSONResponse({"ok":False,"detail":"403 - You do not have access to this page."}, status_code=403)
            except HTTPException as exc:
                return JSONResponse({"ok":False,"detail":exc.detail}, status_code=exc.status_code)
        if path.startswith("/api/detail/"):
            try:
                user = s.user_of(request)
                if user.get("role") == CUSTOMER:
                    return JSONResponse({"ok":False,"detail":"403 - Entity details are not available to Customer accounts."}, status_code=403)
            except HTTPException as exc:
                return JSONResponse({"ok":False,"detail":exc.detail}, status_code=exc.status_code)
        if path in ("/api/freight/attach", "/api/freight/readdoc") and request.method == "POST":
            try:
                user = s.user_of(request)
                if not can_do(user.get("role"), "resolve"):
                    return JSONResponse({"ok":False,"detail":"403 - Your role cannot edit customs documents."}, status_code=403)
            except HTTPException as exc:
                return JSONResponse({"ok":False,"detail":exc.detail}, status_code=exc.status_code)
        # Customer Copilot uses only customer_id-scoped SQL, never the global staff Copilot.
        if path == "/api/copilot":
            try:
                user = s.user_of(request)
                if user.get("role") == CUSTOMER:
                    if not user.get("customer_id"):
                        return JSONResponse({"ok":False,"detail":"Your account is not linked to a customer record. Contact an administrator."}, status_code=403)
                    data = await request.json()
                    question = str(data.get("q","")).strip().lower()[:800]
                    customer_id = user["customer_id"]
                    c = _conn(s)
                    sql = None
                    params = (customer_id,)
                    label = ""
                    if any(x in question for x in ("my quote","my quotes","quote status","quotes")):
                        sql = "SELECT quote_id,shipment_id,carrier,final_price,status,created_at FROM freight_quotes WHERE customer_id=? ORDER BY created_at DESC LIMIT 20"
                        label = "Your latest quotes"
                    elif any(x in question for x in ("my shipment","my shipments","shipment status","shipments")):
                        sql = "SELECT DISTINCT s.shipment_id,s.origin_port,s.dest_port,s.carrier,s.status,s.eta FROM shipments s JOIN freight_quotes q ON q.shipment_id=s.shipment_id WHERE q.customer_id=? ORDER BY s.eta LIMIT 30"
                        label = "Your shipments"
                    else:
                        suggestions = "Try: show my quotes; what is the status of my shipments; show my latest quote."
                        payload = {"ev":"final","text":"I can answer questions only about your own account data. "+suggestions,"sql":"","ms":0}
                        return s.StreamingResponse(iter(["data: "+__import__("json").dumps(payload)+"\\n\\n","data: {\"ev\":\"done\"}\\n\\n"]),media_type="text/event-stream")
                    rows = c.execute(sql,params).fetchall()
                    columns = [x[0] for x in c.execute(sql,params).description] if False else (list(rows[0].keys()) if rows else [])
                    body = "No matching records were found." if not rows else "\\n".join([" | ".join(columns)," | ".join(["---"]*len(columns))]+[" | ".join(str(r[k]) for k in columns) for r in rows])
                    events = [
                        {"ev":"exact","sql":sql,"rows":len(rows)},
                        {"ev":"final","text":"**"+label+"** — "+str(len(rows))+" row(s).\\n\\n"+body,"sql":sql,"ms":0},
                        {"ev":"done"}
                    ]
                    return s.StreamingResponse(iter(["data: "+__import__("json").dumps(x,default=str)+"\\n\\n" for x in events]),media_type="text/event-stream")
            except HTTPException as exc:
                return JSONResponse({"ok":False,"detail":exc.detail}, status_code=exc.status_code)
        return await call_next(request)

    @app.get("/api/profile")
    def profile_get(request: Request):
        u = s.user_of(request)
        c = _conn(s)
        row = c.execute("SELECT id,username,email,role,account_status,created_at,last_login,customer_id FROM users WHERE id=?", (u["id"],)).fetchone()
        if not row: raise HTTPException(404, "User not found")
        return {"ok":True,"user":_public_user(row)}

    @app.put("/api/profile")
    async def profile_update(request: Request):
        u = s.user_of(request); d = await request.json()
        username = str(d.get("username","")).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{2,29}", username):
            raise HTTPException(400, "Username must be 3–30 characters.")
        c = _conn(s)
        clash = c.execute("SELECT 1 FROM users WHERE lower(username)=lower(?) AND id<>?", (username,u["id"])).fetchone()
        if clash: raise HTTPException(409, "That username is already in use.")
        current = str(d.get("current_password",""))
        newp = str(d.get("new_password",""))
        confirm = str(d.get("confirm_password",""))
        if newp:
            row = c.execute("SELECT password_hash FROM users WHERE id=?", (u["id"],)).fetchone()
            if not current or not row or not bcrypt.checkpw(current.encode(), str(row[0]).encode()):
                raise HTTPException(400, "Current password is incorrect.")
            if not _password_ok(newp): raise HTTPException(400, "Password must be 8–64 characters and include uppercase, lowercase, number and special character; spaces are not allowed.")
            if newp != confirm: raise HTTPException(400, "New passwords do not match.")
            if len(newp.encode()) > 72: raise HTTPException(400, "Password is too long.")
            ph = bcrypt.hashpw(newp.encode(), bcrypt.gensalt()).decode()
            c.execute("UPDATE users SET username=?,password_hash=?,failed_attempts=0,account_status='active',lock_until=NULL WHERE id=?", (username,ph,u["id"]))
        else:
            c.execute("UPDATE users SET username=? WHERE id=?", (username,u["id"]))
        c.commit()
        _log(c,u["email"],"profile_updated",u["email"],"Username/password updated")
        c.commit()
        return {"ok":True,"msg":"Profile updated successfully."}

    @app.get("/api/admin/summary")
    def admin_summary(request: Request):
        u = s.user_of(request); need({"role":u["role"]},"users")
        c = _conn(s)
        rows = c.execute("""SELECT id,email,username,role,COALESCE(account_status,'active') status,
            created_at,last_login,customer_id FROM users ORDER BY id""").fetchall()
        roles = {r:0 for r in ROLES}
        for r in c.execute("SELECT role,COUNT(*) n FROM users GROUP BY role"):
            if r[0] in roles: roles[r[0]]=r[1]
        logs = c.execute("SELECT ts,actor,action,target,detail FROM activity_log ORDER BY id DESC LIMIT 50").fetchall()
        return {"ok":True,"users":[dict(x) for x in rows],
                "kpis":{"total":len(rows),"locked":sum(1 for x in rows if x["status"]=="locked"),"per_role":roles},
                "logs":[dict(zip(("ts","actor","action","target","detail"),x)) for x in logs],
                "roles":list(ROLES)}

    @app.post("/api/admin/users")
    async def admin_add_user(request: Request):
        u=s.user_of(request); need({"role":u["role"]},"users"); d=await request.json()
        username=str(d.get("username","")).strip(); email=str(d.get("email","")).strip().lower()
        password=str(d.get("password","")); role=str(d.get("role","Customer"))
        customer_id=str(d.get("customer_id","")).strip() or None
        if role not in ROLES or role==ADMIN and u["role"]!=ADMIN: raise HTTPException(400,"Invalid role.")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{2,29}",username): raise HTTPException(400,"Username must be 3–30 characters.")
        if not re.fullmatch(r"[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\.[A-Za-z]{2,}",email): raise HTTPException(400,"Enter a valid email address.")
        if not _password_ok(password) or len(password.encode())>72: raise HTTPException(400,"Temporary password must satisfy the password policy.")
        c=_conn(s)
        if c.execute("SELECT 1 FROM users WHERE lower(email)=lower(?) OR lower(username)=lower(?)",(email,username)).fetchone(): raise HTTPException(409,"Email or username is already registered.")
        if customer_id and not c.execute("SELECT 1 FROM customers WHERE customer_id=?",(customer_id,)).fetchone(): raise HTTPException(400,"Customer ID does not exist in the customers table.")
        ph=bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()
        c.execute("""INSERT INTO users(username,email,password_hash,role,failed_attempts,account_status,created_at,customer_id)
                     VALUES(?,?,?, ?,0,'active',?,?)""",(username,email,ph,role,_now(),customer_id))
        _log(c,u["email"],"add_user",email,"Created "+role+" account"); c.commit()
        return {"ok":True,"msg":"User created successfully."}

    @app.post("/api/admin/users/{uid}/role")
    async def admin_change_role(uid:int, request:Request):
        u=s.user_of(request); need({"role":u["role"]},"users"); d=await request.json(); role=str(d.get("role",""))
        if role not in ROLES: raise HTTPException(400,"Unknown role.")
        c=_conn(s); target=c.execute("SELECT id,email,role,account_status FROM users WHERE id=?",(uid,)).fetchone()
        if not target: raise HTTPException(404,"User not found.")
        if uid==u["id"]: raise HTTPException(400,"You cannot change your own role.")
        if target["role"]==ADMIN and role!=ADMIN:
            n=c.execute("SELECT COUNT(*) FROM users WHERE role='Admin' AND account_status='active' AND id<>?",(uid,)).fetchone()[0]
            if n==0: raise HTTPException(400,"The last active Admin cannot be demoted.")
        c.execute("UPDATE users SET role=? WHERE id=?",(role,uid))
        _log(c,u["email"],"change_role",target["email"],f"{target['role']} -> {role}"); c.commit()
        return {"ok":True,"msg":"User role updated."}

    @app.post("/api/admin/users/{uid}/lock")
    async def admin_lock(uid:int, request:Request):
        u=s.user_of(request); need({"role":u["role"]},"users"); d=await request.json(); locked=bool(d.get("locked"))
        c=_conn(s); target=c.execute("SELECT id,email,role FROM users WHERE id=?",(uid,)).fetchone()
        if not target: raise HTTPException(404,"User not found.")
        if uid==u["id"] and locked: raise HTTPException(400,"You cannot lock your own account.")
        if locked and target["role"]==ADMIN:
            n=c.execute("SELECT COUNT(*) FROM users WHERE role='Admin' AND account_status='active' AND id<>?",(uid,)).fetchone()[0]
            if n==0: raise HTTPException(400,"The last active Admin cannot be locked.")
        c.execute("UPDATE users SET account_status=?,lock_until=NULL,failed_attempts=0 WHERE id=?",("locked" if locked else "active",uid))
        _log(c,u["email"],"lock_user" if locked else "unlock_user",target["email"],"Account locked" if locked else "Account unlocked")
        c.commit()
        return {"ok":True,"msg":"User locked." if locked else "User unlocked."}

    @app.delete("/api/admin/users/{uid}")
    async def admin_delete(uid:int, request:Request):
        u=s.user_of(request); need({"role":u["role"]},"users")
        c=_conn(s); target=c.execute("SELECT id,email,role FROM users WHERE id=?",(uid,)).fetchone()
        if not target: raise HTTPException(404,"User not found.")
        if uid==u["id"]: raise HTTPException(400,"You cannot delete your own account.")
        if target["role"]==ADMIN:
            n=c.execute("SELECT COUNT(*) FROM users WHERE role='Admin' AND account_status='active' AND id<>?",(uid,)).fetchone()[0]
            if n==0: raise HTTPException(400,"The last active Admin cannot be deleted.")
        _log(c,u["email"],"delete_user",target["email"],"Account deleted")
        c.execute("DELETE FROM users WHERE id=?",(uid,)); c.commit()
        return {"ok":True,"msg":"User deleted."}

    # Extend /api/me with role-filtered menu and account timestamps.
    for route in app.routes:
        if getattr(route,"path",None)=="/api/me" and "GET" in getattr(route,"methods",set()):
            original=route.endpoint
            def wrapped_me(request:Request, _original=original):
                data=_original(request)
                user=s.user_of(request); c=_conn(s)
                row=c.execute("SELECT created_at,last_login,customer_id FROM users WHERE id=?",(user["id"],)).fetchone()
                data["menu"]=_menu(user["role"])
                data["user"].update({"created_at":row["created_at"],"last_login":row["last_login"],"customer_id":row["customer_id"]})
                return data
            route.endpoint=wrapped_me
            route.dependant.call=wrapped_me
            route.app=route.get_route_handler()
            break

    # Patch login success timestamp and signup least-privilege role through endpoint wrapping.
    for route in app.routes:
        if getattr(route,"path",None)=="/api/auth/login" and "POST" in getattr(route,"methods",set()):
            original=route.endpoint
            async def wrapped_login(request:Request,_original=original):
                result=await _original(request)
                if isinstance(result,dict) and result.get("ok") and result.get("user"):
                    c=_conn(s); c.execute("UPDATE users SET last_login=? WHERE id=?",
                                          (_now(),result["user"]["id"])); c.commit()
                return result
            route.endpoint=wrapped_login
            route.dependant.call=wrapped_login
            route.app=route.get_route_handler()
        if getattr(route,"path",None)=="/api/auth/signup" and "POST" in getattr(route,"methods",set()):
            original=route.endpoint
            async def wrapped_signup(request:Request,_original=original):
                # Existing signup creates role='user'; the wrapper updates it to least-privilege Customer.
                result=await _original(request)
                if isinstance(result,dict) and result.get("ok") and result.get("user"):
                    c=_conn(s); c.execute("UPDATE users SET role='Customer',last_login=? WHERE id=?",(_now(),result["user"]["id"])); c.commit()
                    result["user"]["role"]="Customer"
                return result
            route.endpoint=wrapped_signup
            route.dependant.call=wrapped_signup
            route.app=route.get_route_handler()

    # Protect customer quote ownership in the quotes page query. Lock while swapping the module's Q helper.
    try:
        V=s.V
        original_quotes=V.PAGES.get("quotes")
        if original_quotes:
            def scoped_quotes(c,tab=None):
                if c.get("role")!="Customer": return original_quotes(c,tab)
                if not c.get("customer_id"): raise HTTPException(403,"Your account is not linked to a customer record. Contact an administrator.")
                # Render a deliberately minimal customer-only page: no global charts, tickets or staff metrics.
                ports = s.B.Q("SELECT port_name FROM ports ORDER BY port_name").port_name.tolist()
                cargos = list(s.V.dom.CARGO)
                quote_form = s.B.form("quote", [
                    {"name":"o","label":"Origin","type":"select","options":ports,"value":ports[0] if ports else ""},
                    {"name":"d","label":"Destination","type":"select","options":ports,"value":ports[1] if len(ports)>1 else (ports[0] if ports else "")},
                    {"name":"cargo","label":"Cargo","type":"select","options":cargos,"value":cargos[0] if cargos else "General"},
                    {"name":"weight","label":"Weight (tons)","type":"number","value":120,"min":1,"max":5000},
                    {"name":"hs","label":"HS code","type":"text","value":"HS-8501"}
                ], "Generate quote", "/api/freight/quote", title="Create a quote", sub="This quote will be created only for your linked customer account.")
                df = s.B.Q("SELECT quote_id,shipment_id,carrier,final_price,margin_pct,status,created_at FROM freight_quotes WHERE customer_id=? ORDER BY created_at DESC LIMIT 100", (c["customer_id"],))
                bl = [quote_form, s.B.kpis(("Your quotes", int(len(df))), ("Approved", int((df.status == "Approved").sum()) if len(df) else 0), ("Pending", int((df.status == "Pending Approval").sum()) if len(df) else 0))]
                bl.append(s.B.table(df, ["quote_id","shipment_id","carrier",s.B.num_col("final_price","price","money"),s.B.num_col("margin_pct","margin %","num"),s.B.pill_col("status"),"created_at"], title="Your latest quotes", h=340, key="customer_quotes"))
                return s.B.page("My Quotes", "Only records linked to your customer account are shown.", bl, live=30)
            V.PAGES["quotes"]=scoped_quotes
    except Exception:
        pass

    # Ensure admin is initialized only after the base database startup/seed has completed.
    @app.on_event("startup")
    def _milestone2_after_startup():
        _ensure_schema(s)

