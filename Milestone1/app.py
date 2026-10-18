import os
import re
import time
import sqlite3
import secrets
import smtplib
import hashlib
import html
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import bcrypt
import jwt
import streamlit as st

# ---------------------------------------------------------------------
# Agentic AI for Maritime Freight Pricing and Route Optimization
# Milestone 1: User Authentication Module
# Secrets must be configured in Colab Secrets / environment variables.
# ---------------------------------------------------------------------
DB_PATH = os.getenv("AUTH_DB_PATH", "milestone1_users.db")
JWT_SECRET = os.getenv("JWT_SECRET", "")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
OTP_EXPIRY_MINUTES = 5

st.set_page_config(
    page_title="Maritime AI | Milestone 1",
    page_icon="⚓",
    layout="wide",
    initial_sidebar_state="collapsed",
)

SECURITY_QUESTIONS = [
    "What was the name of your first school?",
    "What is your favourite city?",
    "What was the name of your first pet?",
    "What is your favourite childhood nickname?",
]

# Professional navy / teal theme. This is real CSS, not displayed as text.
st.markdown("""
<style>
:root { --navy:#102A43; --blue:#176B87; --teal:#2A9D8F; --ink:#172B4D; --muted:#627D98; }
.stApp { background: linear-gradient(135deg, #F2F7FA 0%, #EAF1F7 55%, #F7FAFC 100%); color:var(--ink); }
.block-container { max-width: 1120px; padding-top: 1.6rem; padding-bottom: 2.5rem; }
.brand-banner { background:linear-gradient(120deg,#102A43,#176B87); color:white; padding:25px 30px; border-radius:18px; margin-bottom:22px; box-shadow:0 12px 28px rgba(16,42,67,.16); }
.brand-eyebrow { font-size:12px; letter-spacing:2px; font-weight:800; color:#A8DADC; text-transform:uppercase; margin-bottom:8px; }
.brand-title { font-size:clamp(22px,3vw,32px); font-weight:750; line-height:1.25; margin:0; color:white; }
.brand-subtitle { margin-top:9px; color:#E6F4F7; font-size:15px; }
.page-title { font-size:28px; font-weight:750; color:#102A43; margin:10px 0 4px 0; }
.page-hint { color:#627D98; margin-bottom:18px; }
div[data-testid="stForm"] { background:rgba(255,255,255,.92); border:1px solid #D6E2EC; border-radius:16px; padding:24px; box-shadow:0 8px 22px rgba(16,42,67,.06); }
div[data-testid="stTextInput"] label, div[data-testid="stSelectbox"] label, div[data-testid="stRadio"] label { color:#243B53; font-weight:600; }
.stTextInput input { border-radius:9px; }
.stButton > button, div[data-testid="stFormSubmitButton"] > button { border-radius:9px; min-height:43px; font-weight:650; border:1px solid #176B87; transition:all .15s ease; }
.stButton > button[kind="primary"], div[data-testid="stFormSubmitButton"] > button[kind="primary"] { background:linear-gradient(100deg,#176B87,#2A9D8F); color:white; }
.stButton > button:hover, div[data-testid="stFormSubmitButton"] > button:hover { border-color:#2A9D8F; color:#102A43; }
div[data-testid="stTabs"] button { font-weight:700; }
div[data-testid="stTabs"] button[aria-selected="true"] { color:#176B87; }
.dashboard-card { background:white; padding:24px; border:1px solid #D6E2EC; border-radius:16px; box-shadow:0 8px 22px rgba(16,42,67,.06); }
.footer-note { color:#627D98; font-size:12px; border-top:1px solid #D6E2EC; padding-top:16px; margin-top:26px; }
div[data-testid="stAlert"] { border-radius:10px; }
@media (max-width: 700px) {
 .block-container { padding:1rem 1rem 2rem; }
 .brand-banner { padding:20px; }
 div[data-testid="stForm"] { padding:16px; }
}
</style>
""", unsafe_allow_html=True)


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash BLOB NOT NULL,
                security_question TEXT NOT NULL,
                security_answer_hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def hash_password(value: str) -> bytes:
    return bcrypt.hashpw(value.encode("utf-8"), bcrypt.gensalt())


def check_password(value: str, stored_hash) -> bool:
    try:
        return bcrypt.checkpw(value.encode("utf-8"), bytes(stored_hash))
    except (ValueError, TypeError):
        return False


def valid_email(email: str) -> bool:
    # Assignment rule: at least 2 letters before @, before final dot, and after final dot.
    return bool(re.fullmatch(
        r"[A-Za-z]{2,}[A-Za-z0-9._%+-]*@[A-Za-z]{2,}[A-Za-z0-9.-]*\.[A-Za-z]{2,}",
        email
    ))


def password_problem(password: str):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special symbol."
    return None


def make_jwt(username: str, email: str, role: str = "user") -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not configured in Colab Secrets.")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email.lower(),
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=2),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_jwt(token: str):
    if not token or not JWT_SECRET:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def find_user(identifier: str):
    identifier = identifier.strip().lower()
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE lower(username)=? OR lower(email)=?",
            (identifier, identifier),
        ).fetchone()


def update_password(email: str, new_password: str):
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET password_hash=? WHERE lower(email)=?",
            (hash_password(new_password), email.strip().lower()),
        )


def send_otp_email(to_email: str, otp: str):
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return False, "Email sending is not configured. Add EMAIL_ADDRESS and EMAIL_PASSWORD in Colab Secrets."
    msg = EmailMessage()
    msg["Subject"] = "Milestone 1 password reset verification code"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    msg.set_content(
        f"Your password reset verification code is {otp}.\n"
        f"It expires in {OTP_EXPIRY_MINUTES} minutes. If you did not request this, ignore this email."
    )
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
        return True, "OTP email sent."
    except Exception:
        return False, "Could not send the email. Check Gmail settings and the App Password in Colab Secrets."


def clear_reset_state():
    for key in (
        "reset_email", "reset_question", "reset_otp_hash", "reset_otp_expiry",
        "reset_otp_verified", "reset_mode"
    ):
        st.session_state.pop(key, None)


def go_to(page: str):
    st.session_state.page = page
    st.rerun()


def show_brand_header():
    st.markdown("""
    <div class="brand-banner">
      <div class="brand-eyebrow">⚓ Agentic AI Project</div>
      <div class="brand-title">Agentic AI for Maritime Freight Pricing and Route Optimization</div>
      <div class="brand-subtitle">Milestone 1 &nbsp;·&nbsp; User Authentication Module</div>
    </div>
    """, unsafe_allow_html=True)


init_db()
defaults = {
    "page": "Login",
    "jwt_token": None,
    "login_kind": "user",
    "reset_email": None,
    "reset_question": None,
    "reset_otp_hash": None,
    "reset_otp_expiry": None,
    "reset_otp_verified": False,
    "reset_mode": None,
}
for key, default in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = default

payload = decode_jwt(st.session_state.get("jwt_token"))
if st.session_state.get("jwt_token") and not payload:
    st.session_state.jwt_token = None
    st.session_state.page = "Login"
    st.warning("Your session expired. Please log in again.")

show_brand_header()

# Main-page navigation (not in the sidebar): Login and Signup appear first.
public_pages = ["Login", "Signup", "Forgot Password", "Admin Login"]
if not st.session_state.get("jwt_token"):
    current = st.session_state.page if st.session_state.page in public_pages else "Login"
    tabs = st.tabs(public_pages)
    for tab, page in zip(tabs, public_pages):
        with tab:
            if page == "Login":
                st.markdown('<div class="page-title">Welcome back</div>', unsafe_allow_html=True)
                st.markdown('<div class="page-hint">Sign in to access your account.</div>', unsafe_allow_html=True)
                with st.form("login_form"):
                    identifier = st.text_input("Username or email")
                    password = st.text_input("Password", type="password")
                    submitted = st.form_submit_button("Login", use_container_width=True, type="primary")
                if submitted:
                    identifier = identifier.strip()
                    if not identifier or not password:
                        st.error("Please enter both username/email and password.")
                    else:
                        user = find_user(identifier)
                        if user and check_password(password, user["password_hash"]):
                            try:
                                st.session_state.jwt_token = make_jwt(user["username"], user["email"], "user")
                                st.session_state.login_kind = "user"
                                st.rerun()
                            except RuntimeError as exc:
                                st.error(str(exc))
                        else:
                            st.error("Invalid username/email or password.")
                if st.button("Forgot your password?", key="login_forgot"):
                    go_to("Forgot Password")
                st.caption("New here? Select the Signup tab above.")

            elif page == "Signup":
                st.markdown('<div class="page-title">Create your account</div>', unsafe_allow_html=True)
                st.markdown('<div class="page-hint">Use a valid email and create a strong password.</div>', unsafe_allow_html=True)
                with st.form("signup_form"):
                    username = st.text_input("Username", max_chars=50).strip()
                    email = st.text_input("Email address").strip().lower()
                    password = st.text_input("Password", type="password")
                    confirm_password = st.text_input("Confirm password", type="password")
                    question = st.selectbox("Security question", SECURITY_QUESTIONS)
                    answer = st.text_input("Security answer", type="password").strip()
                    st.caption("Password needs 8+ characters, uppercase, lowercase, a number and a special symbol.")
                    submitted = st.form_submit_button("Create account", use_container_width=True, type="primary")
                if submitted:
                    if not all([username, email, password, confirm_password, question, answer]):
                        st.error("Please fill in every required field.")
                    elif len(username) < 2:
                        st.error("Username must contain at least 2 characters.")
                    elif not valid_email(email):
                        st.error("Enter a valid email address (for example, ab@cd.ef).")
                    elif (problem := password_problem(password)):
                        st.error(problem)
                    elif password != confirm_password:
                        st.error("Password and Confirm Password must match exactly.")
                    else:
                        try:
                            with get_connection() as conn:
                                conn.execute(
                                    "INSERT INTO users (username,email,password_hash,security_question,security_answer_hash,created_at) VALUES (?,?,?,?,?,?)",
                                    (username, email, hash_password(password), question,
                                     hash_password(answer.lower()), datetime.now(timezone.utc).isoformat()),
                                )
                            st.success("Account created successfully. Please select Login.")
                        except sqlite3.IntegrityError:
                            st.error("That username or email is already registered. Please choose another.")

            elif page == "Forgot Password":
                st.markdown('<div class="page-title">Recover your account</div>', unsafe_allow_html=True)
                st.markdown('<div class="page-hint">Reset using your security answer or email verification code.</div>', unsafe_allow_html=True)
                route = st.radio("Recovery method", ["Security question", "Email OTP"], horizontal=True, key="recovery_route")

                if route == "Security question":
                    with st.form("security_lookup_form"):
                        username_lookup = st.text_input("Registered username").strip()
                        lookup = st.form_submit_button("Find security question", use_container_width=True, type="primary")
                    if lookup:
                        user = find_user(username_lookup)
                        if user and username_lookup.lower() == user["username"].lower():
                            st.session_state.reset_email = user["email"]
                            st.session_state.reset_question = user["security_question"]
                            st.session_state.reset_mode = "security"
                        else:
                            st.error("Account not found. Check the username and try again.")
                    if st.session_state.get("reset_mode") == "security" and st.session_state.get("reset_email"):
                        st.info("Security question: " + st.session_state.reset_question)
                        with st.form("security_reset_form"):
                            answer = st.text_input("Security answer", type="password").strip()
                            new_password = st.text_input("New password", type="password")
                            confirm_new = st.text_input("Confirm new password", type="password")
                            reset = st.form_submit_button("Reset password", use_container_width=True, type="primary")
                        if reset:
                            user = find_user(st.session_state.reset_email)
                            if not answer or not new_password or not confirm_new:
                                st.error("Please fill in every required field.")
                            elif (problem := password_problem(new_password)):
                                st.error(problem)
                            elif new_password != confirm_new:
                                st.error("Password and Confirm Password must match exactly.")
                            elif not user or not check_password(answer.lower(), user["security_answer_hash"]):
                                st.error("Incorrect security answer.")
                            else:
                                update_password(st.session_state.reset_email, new_password)
                                clear_reset_state()
                                st.success("Password updated. Please log in with your new password.")

                else:
                    if not st.session_state.get("reset_otp_verified"):
                        with st.form("otp_request_form"):
                            otp_email = st.text_input("Registered email address").strip().lower()
                            send_clicked = st.form_submit_button("Send OTP", use_container_width=True, type="primary")
                        if send_clicked:
                            if not otp_email:
                                st.error("Please enter your registered email address.")
                            elif not valid_email(otp_email):
                                st.error("Enter a valid email address.")
                            else:
                                user = find_user(otp_email)
                                if not user or user["email"].lower() != otp_email:
                                    st.error("If the account exists, an OTP can be sent to its registered email.")
                                else:
                                    otp = f"{secrets.randbelow(1_000_000):06d}"
                                    ok, message = send_otp_email(otp_email, otp)
                                    if ok:
                                        st.session_state.reset_email = otp_email
                                        st.session_state.reset_otp_hash = hashlib.sha256(otp.encode()).hexdigest()
                                        st.session_state.reset_otp_expiry = time.time() + OTP_EXPIRY_MINUTES * 60
                                        st.session_state.reset_otp_verified = False
                                        st.session_state.reset_mode = "otp"
                                        st.success("OTP sent. Check your email inbox and spam folder.")
                                    else:
                                        st.error(message)

                        if st.session_state.get("reset_otp_hash") and st.session_state.get("reset_email"):
                            with st.form("otp_verify_form"):
                                entered_otp = st.text_input("Enter 6-digit OTP", max_chars=6)
                                verify_clicked = st.form_submit_button("Verify OTP", use_container_width=True, type="primary")
                            if verify_clicked:
                                if time.time() > (st.session_state.get("reset_otp_expiry") or 0):
                                    st.session_state.reset_otp_hash = None
                                    st.error("OTP expired. Please request a new one.")
                                elif not re.fullmatch(r"\d{6}", entered_otp or ""):
                                    st.error("Enter the 6-digit OTP.")
                                elif not secrets.compare_digest(hashlib.sha256(entered_otp.encode()).hexdigest(), st.session_state.reset_otp_hash):
                                    st.error("Incorrect OTP. Please try again.")
                                else:
                                    st.session_state.reset_otp_verified = True
                                    st.success("OTP verified. You can now set a new password.")
                                    st.rerun()
                    else:
                        st.info("Email verified: " + st.session_state.reset_email)
                        with st.form("otp_new_password_form"):
                            new_password = st.text_input("New password", type="password")
                            confirm_new = st.text_input("Confirm new password", type="password")
                            reset = st.form_submit_button("Update password", use_container_width=True, type="primary")
                        if reset:
                            if time.time() > (st.session_state.get("reset_otp_expiry") or 0):
                                clear_reset_state()
                                st.error("OTP verification expired. Please start again.")
                            elif not new_password or not confirm_new:
                                st.error("Please fill in both password fields.")
                            elif (problem := password_problem(new_password)):
                                st.error(problem)
                            elif new_password != confirm_new:
                                st.error("Password and Confirm Password must match exactly.")
                            else:
                                update_password(st.session_state.reset_email, new_password)
                                clear_reset_state()
                                st.success("Password updated. Please log in.")

                if st.button("Back to Login", key="forgot_back"):
                    clear_reset_state()
                    go_to("Login")

            else:  # Admin Login
                st.markdown('<div class="page-title">Administrator access</div>', unsafe_allow_html=True)
                st.markdown('<div class="page-hint">Admin credentials are configured separately in Colab Secrets.</div>', unsafe_allow_html=True)
                with st.form("admin_login_form"):
                    admin_username = st.text_input("Admin username")
                    admin_password = st.text_input("Admin password", type="password")
                    submitted = st.form_submit_button("Admin Login", use_container_width=True, type="primary")
                if submitted:
                    if not admin_username or not admin_password:
                        st.error("Please fill in both admin fields.")
                    elif not ADMIN_USERNAME or not ADMIN_PASSWORD:
                        st.error("Admin credentials are not configured in Colab Secrets yet.")
                    elif secrets.compare_digest(admin_username, ADMIN_USERNAME) and secrets.compare_digest(admin_password, ADMIN_PASSWORD):
                        try:
                            st.session_state.jwt_token = make_jwt(ADMIN_USERNAME, "admin@local.invalid", "admin")
                            st.session_state.login_kind = "admin"
                            st.rerun()
                        except RuntimeError as exc:
                            st.error(str(exc))
                    else:
                        st.error("Invalid admin username or password.")

else:
    payload = decode_jwt(st.session_state.get("jwt_token"))
    if not payload:
        st.session_state.jwt_token = None
        st.session_state.page = "Login"
        st.rerun()

    if payload.get("role") == "admin":
        st.markdown('<div class="page-title">Admin dashboard</div>', unsafe_allow_html=True)
        st.markdown('<div class="dashboard-card">You are signed in with administrator access. Only usernames and email addresses are shown; password data is never displayed.</div>', unsafe_allow_html=True)
        with get_connection() as conn:
            rows = conn.execute("SELECT username, email, created_at FROM users ORDER BY created_at DESC").fetchall()
        if rows:
            st.dataframe([dict(row) for row in rows], use_container_width=True, hide_index=True)
        else:
            st.info("No registered users yet.")
    else:
        safe_username = html.escape(str(payload.get("username", "user")))
        safe_email = html.escape(str(payload.get("sub", "")))
        st.markdown(
            f'<div class="dashboard-card"><div class="page-title">Welcome, {safe_username}!</div>'
            f'<p>You are logged in successfully.</p><p><b>Account email:</b> {safe_email}</p>'
            '<p style="color:#627D98">Your signed JWT session expires after two hours.</p></div>',
            unsafe_allow_html=True,
        )

    if st.button("Logout", type="primary", use_container_width=True):
        st.session_state.jwt_token = None
        st.session_state.login_kind = "user"
        clear_reset_state()
        st.session_state.page = "Login"
        st.rerun()

st.markdown(
    '<div class="footer-note">Internship practice project · Do not use real sensitive accounts or production data.</div>',
    unsafe_allow_html=True,
)
