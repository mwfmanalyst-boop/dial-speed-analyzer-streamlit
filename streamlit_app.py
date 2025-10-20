# app.py
import os
import io
import json
import time
import shutil
import hashlib
from datetime import datetime, timedelta, date
from dateutil import tz
from typing import Dict, List, Tuple, Optional, Set

import bcrypt
import duckdb
import pandas as pd
import streamlit as st
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload
from googleapiclient.errors import HttpError
from streamlit_option_menu import option_menu

# -------------------------------------------------------------------
# App config
# -------------------------------------------------------------------
st.set_page_config(page_title="Dial Speed Analyzer", page_icon="📞", layout="wide")
ASIA_KOLKATA = tz.gettz("Asia/Kolkata")
DATE_FMT_QUERY = "%Y-%m-%d"
LOCAL_CACHE_DIR = "drive_cache"
DEFAULT_PERCENTILES = (95, 90, 85)
UNRECOMMENDED_CAMPAIGNS = st.secrets.get(
    "unrecommended",
    [
        "CMB_FRAUD_English",
        "CMB_FRAUD_Hindi",
        "CMB_Large_Smartphones_English",
        "CMB_Large_Smartphones_Hindi",
        "CMB_Large_Smartphones_Kannada",
        "CMB_Large_Smartphones_Tamil",
    ],
)

# -------------------------------------------------------------------
# Global CSS (background, tables, metric cards)
# -------------------------------------------------------------------
GLOBAL_CSS = """
<style>
/* animated background */
@keyframes bg_grad {
  0% {background-position:0% 50%}
  50% {background-position:100% 50%}
  100% {background-position:0% 50%}
}
body, .stApp {
  background: linear-gradient(-45deg, #e0e7ff, #c2d2ff, #f0e6ff, #ffe2e6);
  background-size: 400% 400%;
  animation: bg_grad 15s ease infinite;
}

/* hide chrome only while on login */
.login-mode .stApp > header,
.login-mode [data-testid="stSidebar"],
.login-mode [data-testid="stToolbar"],
.login-mode [data-testid="stDecoration"],
.login-mode [data-testid="stFooter"] { display:none !important; }
.login-mode html, .login-mode body, .login-mode .stApp,
.login-mode [data-testid="stAppViewContainer"], .login-mode .block-container{
  height:100vh !important; max-height:100vh !important; overflow:hidden !important; padding:0 !important;
}

/* ---------- DataFrame rules (robust for old/new renderers) ---------- */
div[data-testid="stDataFrame"]{ margin:0 auto; }
div[data-testid="stDataFrame"] table{ table-layout:fixed !important; width:100% !important; }
div[data-testid="stDataFrame"] td, div[data-testid="stDataFrame"] th{
  text-align:center !important; vertical-align:middle !important;
}
div[data-testid="stDataFrame"] [role="gridcell"],
div[data-testid="stDataFrame"] [role="columnheader"]{
  display:flex !important; justify-content:center !important; align-items:center !important; text-align:center !important;
}
/* gradient table header (thead + grid header) */
div[data-testid="stDataFrame"] thead th,
div[data-testid="stDataFrame"] [role="columnheader"]{
  background: linear-gradient(90deg,#6366f1 0%, #22d3ee 100%) !important;
  color:#fff !important; font-weight:800 !important; border:none !important;
}
div[data-testid="stDataFrame"] thead th:nth-child(2n),
div[data-testid="stDataFrame"] [role="columnheader"]:nth-child(2n){
  background: linear-gradient(90deg,#f59e0b 0%, #ef4444 100%) !important;
}
div[data-testid="stDataFrame"] thead th:nth-child(3n),
div[data-testid="stDataFrame"] [role="columnheader"]:nth-child(3n){
  background: linear-gradient(90deg,#10b981 0%, #06b6d4 100%) !important;
}
div[data-testid="stDataFrame"] [data-testid="columnResizer"],
div[data-testid="stDataFrame"] [class*="columnResizer"]{ display:none !important; }

/* metric cards (3-D gradients) */
.metric-card{
  --c1:#60a5fa; --c2:#3b82f6;
  border-radius:18px; padding:18px 20px; color:#fff; border:2px solid transparent;
  background:
    linear-gradient(145deg, rgba(255,255,255,.14), rgba(255,255,255,.06)) padding-box,
    linear-gradient(135deg,var(--c1),var(--c2)) border-box;
  box-shadow: 0 20px 40px rgba(31,38,135,.22), inset 0 1px 0 rgba(255,255,255,.45);
  transition: transform .18s ease, box-shadow .18s ease; backdrop-filter: blur(6px);
}
.metric-card:hover{ transform: translateY(-4px); box-shadow:0 26px 56px rgba(31,38,135,.28), inset 0 1px 0 rgba(255,255,255,.55); }
.metric-title{ font-weight:800; font-size:18px; display:flex; align-items:center; gap:10px; margin:0 0 6px 0; }
.metric-value{ font-size:28px; font-weight:800; line-height:1; }
.mc-0{ --c1:#60a5fa; --c2:#3b82f6; }  /* blue */
.mc-1{ --c1:#f59e0b; --c2:#ef4444; }  /* orange→red */
.mc-2{ --c1:#34d399; --c2:#10b981; }  /* green */
.mc-3{ --c1:#a78bfa; --c2:#6366f1; }  /* purple */
.mc-4{ --c1:#fb7185; --c2:#f472b6; }  /* pink */

/* tidy footer */
footer{ visibility:hidden; }
</style>
"""
st.markdown(GLOBAL_CSS, unsafe_allow_html=True)

# -------------------------------------------------------------------
# Auth helpers
# -------------------------------------------------------------------
def hash_email(email: str) -> str:
    return "sha256:" + hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()

def check_password(plain: str, hashed_bcrypt: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed_bcrypt.encode("utf-8"))
    except Exception:
        return False

def get_auth_users() -> List[Dict]:
    auth = st.secrets.get("auth", {})
    users = auth.get("users", [])
    if isinstance(users, dict):
        users = [users]
    return users

# -------------------------------------------------------------------
# Login Gate (all fixes baked in)
# -------------------------------------------------------------------
def login_gate() -> Optional[Dict]:
    if "auth_user" in st.session_state:
        return st.session_state["auth_user"]

    users = get_auth_users()
    if not users:
        st.error("Authentication is not configured.")
        st.stop()

    # enable login mode (hide chrome)
    st.markdown('<script>document.body.classList.add("login-mode");</script>', unsafe_allow_html=True)

    # scoped login CSS (no malformed comments, robust red button)
    st.markdown("""
    <style>
    .block-container{max-width:1100px !important;} /* tighter gap between the two cards */

    /* Left hero */
    .hero3d{
      position:relative; height:560px; border-radius:26px; padding:48px; color:#fff;
      background:linear-gradient(135deg,#6366f1 0%, #7c3aed 45%, #9333ea 100%);
      box-shadow:0 30px 60px rgba(99,102,241,.35), inset 0 1px 0 rgba(255,255,255,.25);
      overflow:hidden; transform:translateZ(0);
    }
    @media (hover:hover){ .hero3d:hover{ transform: translateY(-6px) rotateX(1.5deg) rotateY(-1.5deg); } }
    .float-wrap{ position:absolute; inset:0; pointer-events:none; }
    .blob{ position:absolute; width:160px; height:160px; border-radius:24px; filter:blur(6px); opacity:.22; animation:updown 7s ease-in-out infinite; }
    .blob.b1{ left:-40px; top:40px;  background:linear-gradient(135deg,#60a5fa,#3b82f6);  animation-delay:.1s; }
    .blob.b2{ right:-20px; top:110px; background:linear-gradient(135deg,#f472b6,#fb7185); animation-delay:.8s; }
    .blob.b3{ left:90px; bottom:-30px; background:linear-gradient(135deg,#34d399,#10b981); animation-delay:1.4s; }
    @keyframes updown{0%,100%{transform:translateY(0)}50%{transform:translateY(-18px)}}

    .hero-icon{
      position: relative; width:96px; height:96px; border-radius:22px; display:grid; place-items:center;
      background: linear-gradient(145deg, rgba(255,255,255,.22), rgba(255,255,255,.10));
      border:1px solid rgba(255,255,255,.30);
      backdrop-filter: blur(6px);
      box-shadow: inset 0 1px 0 rgba(255,255,255,.45), 0 22px 44px rgba(0,0,0,.25);
    }
    .phone-emoji{
      font-size:46px; line-height:1; color:#ef4444;
      filter: drop-shadow(0 6px 12px rgba(0,0,0,.35));
      transform-origin: 50% 10%;
      animation: ring 1.6s ease-in-out infinite;
    }
    .hero-icon::before,.hero-icon::after{
      content:""; position:absolute; inset:0; border-radius:22px; pointer-events:none;
      border:2px solid rgba(255,255,255,.55); opacity:.6; transform:scale(1);
      animation: ping 1.6s ease-out infinite;
    }
    .hero-icon::after{ animation-delay:.6s; opacity:.4; }
    @keyframes ring{ 0%{transform:rotate(0)}10%{transform:rotate(14deg)}20%{transform:rotate(-10deg)}30%{transform:rotate(12deg)}40%{transform:rotate(-8deg)}50%{transform:rotate(6deg)}60%,100%{transform:rotate(0)} }
    @keyframes ping{0%{transform:scale(1);opacity:.65}80%{transform:scale(1.8);opacity:0}100%{transform:scale(2.1);opacity:0}}

    .hero-badges{ margin-top:18px; display:flex; gap:10px; flex-wrap:wrap; }
    .badge{
      padding:10px 14px; border-radius:16px; background:rgba(255,255,255,.18);
      font-weight:700; font-size:12px; color:#fff; backdrop-filter: blur(4px);
      border:1px solid rgba(255,255,255,.25); box-shadow:0 8px 20px rgba(0,0,0,.12), inset 0 1px 0 rgba(255,255,255,.35);
    }
    .badge.float{ animation:bob 5.5s ease-in-out infinite; } .delay1{animation-delay:0s;} .delay2{animation-delay:.9s;} .delay3{animation-delay:1.8s;}
    @keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}

    /* Right login card */
    [data-testid="stForm"]{
      position:relative; border-radius:26px; padding:40px 36px 46px;
      overflow:visible; min-height:560px;
      border:1px solid rgba(99,102,241,.16);
      background:
        linear-gradient(180deg, rgba(255,255,255,.94), rgba(250,250,250,.96)) padding-box,
        linear-gradient(-45deg,#f0abfc,#93c5fd,#a7f3d0,#fecaca) border-box;
      background-clip: padding-box, border-box;
      background-size: 100% 100%, 300% 300%;
      animation: cardShift 12s ease infinite;
      box-shadow: 0 26px 62px rgba(31,38,135,.18), 0 0 0 1px rgba(255,255,255,.85) inset;
    }
    @keyframes cardShift{0%{background-position:0% 50%,0% 50%}50%{background-position:0% 50%,100% 50%}100%{background-position:0% 50%,0% 50%}}

    [data-testid="stForm"]::before,[data-testid="stForm"]::after{
      position:absolute; display:grid; place-items:center; width:62px; height:62px; border-radius:18px; pointer-events:none;
      backdrop-filter: blur(6px); background: rgba(255,255,255,.22); border:1px solid rgba(99,102,241,.28);
      box-shadow: 0 12px 24px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.45); font-size:28px; text-shadow:0 3px 8px rgba(0,0,0,.25);
      content:'🔒'; color:#ef4444;
    }
    [data-testid="stForm"]::before{ top:14px; right:14px; animation:float1 6s ease-in-out infinite; }
    [data-testid="stForm"]::after{ content:'⚡'; color:#f59e0b; bottom:14px; left:14px; animation:float2 6.5s ease-in-out infinite; }
    @keyframes float1{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
    @keyframes float2{0%,100%{transform:translateY(0)}50%{transform:translateY(8px)}}

    /* inputs */
    [data-testid="stForm"] div[data-baseweb="input"]{
      border-radius:12px !important; border:1px solid #e5e7eb !important; box-shadow:none !important;
      transition:border-color .15s ease, box-shadow .15s ease;
    }
    [data-testid="stForm"] div[data-baseweb="input"]:hover{ border-color:#d1d5db !important; }
    [data-testid="stForm"] div[data-baseweb="input"]:focus-within{
      border-color:#a78bfa !important; box-shadow:0 0 0 3px rgba(99,102,241,.18) inset !important;
    }
    [data-testid="stForm"] .stTextInput>div>div>input{ border:0 !important; padding:14px 12px !important; }
    [data-testid="stForm"] .stTextInput{ margin-bottom:12px; }
    [data-testid="stForm"] label{ font-weight:600; color:#374151; }

    /* gradient title */
    .gradient-title{
      font-weight:800; font-size:32px; margin:0 0 6px 0;
      background: linear-gradient(90deg,#111827,#ef4444,#7c3aed,#111827);
      -webkit-background-clip:text; background-clip:text; color:transparent;
      background-size:200% 100%; animation: shimmer 10s linear infinite;
    }
    @keyframes shimmer{0%{background-position:0% 50%}100%{background-position:200% 50%}}

    /* FORCE the submit button to be red & 3D no matter where Streamlit mounts it */
    .login-btn-wrap button,
    .stButton button,
    button[data-testid="baseButton-primary"],
    button[data-testid="baseButton-secondary"]{
      width:100% !important; padding:14px 16px !important; border-radius:12px !important;
      font-weight:800 !important; letter-spacing:.2px !important; border:0 !important;
      background:linear-gradient(180deg,#ef4444,#dc2626) !important; color:#fff !important;
      box-shadow:0 12px 28px rgba(239,68,68,.45), inset 0 -2px 0 rgba(0,0,0,.15) !important;
      transition:transform .06s, box-shadow .2s, background .2s !important;
    }
    .stButton button:hover{
      background:linear-gradient(180deg,#f05252,#d11f1f) !important; transform:translateY(-1px) !important;
      box-shadow:0 16px 34px rgba(239,68,68,.50), inset 0 -2px 0 rgba(0,0,0,.18) !important;
    }
    .stButton button:active{ transform:translateY(1px) !important; box-shadow:0 8px 18px rgba(239,68,68,.40), inset 0 -2px 0 rgba(0,0,0,.22) !important; }
    </style>
    """, unsafe_allow_html=True)

    left, right = st.columns([1, 1], gap="small")  # tighter gap

    with left:
        st.markdown("""
        <div class="hero3d">
          <div class="float-wrap"><div class="blob b1"></div><div class="blob b2"></div><div class="blob b3"></div></div>
          <div class="hero-icon"><span class="phone-emoji" role="img" aria-label="phone">📞</span></div>
          <div style="margin-top:22px;">
            <h1 style="font-size:42px; line-height:1.15; margin:18px 0 8px 0;">Welcome Back</h1>
            <p style="opacity:.95; margin:0; font-size:16px;">Log in to view the Dialspeed Dashboard and explore new features analytics.</p>
            <div class="hero-badges">
              <div class="badge float delay1">🔒 Secure</div>
              <div class="badge float delay2">⚡ Fast</div>
              <div class="badge float delay3">📊 Analytics</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with right:
        with st.form("login_form", clear_on_submit=False):
            st.markdown(
                '<h2 class="gradient-title">Login 👤</h2>'
                '<p style="color:#6b7280; margin:0 0 18px 0;">Use your work account</p>',
                unsafe_allow_html=True
            )
            email = st.text_input("Email 📧", placeholder="you@company.com")
            password = st.text_input("Password 🔑", type="password", placeholder="••••••••")
            st.markdown('<div class="login-btn-wrap">', unsafe_allow_html=True)
            submit = st.form_submit_button("Login", use_container_width=True, type="primary")
            st.markdown('</div>', unsafe_allow_html=True)

        # tiny JS to tag the real "Login" button in case Streamlit remounts it
        st.markdown("""
        <script>
        (function(){
          function tagLogin(){
            const btn = Array.from(document.querySelectorAll('button')).find(b => (b.innerText||'').trim()==='Login');
            if(btn) btn.classList.add('force-red'); // class exists in global CSS targets above
          }
          tagLogin();
          new MutationObserver(tagLogin).observe(document.body,{subtree:true, childList:true});
        })();
        </script>
        """, unsafe_allow_html=True)

        if submit:
            email_hash = hash_email(email)
            rec = next((u for u in users if u.get("email_hash") == email_hash), None)
            if rec and check_password(password, rec.get("password_bcrypt", "")):
                st.session_state["auth_user"] = {
                    "name": rec.get("name", "User"),
                    "email_hash": email_hash,
                    "role": rec.get("role", "user"),  # <-- add role (defaults to user)
                }
                st.markdown('<script>document.body.classList.remove("login-mode");</script>', unsafe_allow_html=True)
                st.rerun()
            else:
                st.error("Incorrect email or password.")

        st.markdown(
            '<p style="text-align:center; margin-top:10px; color:#6b7280;">Need help? Contact your system administrator.</p>',
            unsafe_allow_html=True
        )

    st.stop()

# authenticate (halts inside login until success)
user = login_gate() or {}
IS_ADMIN = (user.get("role", "user").lower() == "admin")

# restore normal chrome after login
st.markdown('<script>document.body.classList.remove("login-mode");</script>', unsafe_allow_html=True)
st.markdown('<div class="main-content">', unsafe_allow_html=True)

# -------------------------------------------------------------------
# Drive helpers
# -------------------------------------------------------------------
@st.cache_resource(show_spinner="Connecting to Database Server...")
def get_drive_service():
    if "gcp_service_account" not in st.secrets:
        raise RuntimeError("Service account missing. Add [gcp_service_account] to secrets.")
    info = st.secrets["gcp_service_account"]
    if isinstance(info, str):
        info = json.loads(info)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/drive"]
    )
    return build("drive", "v3", credentials=creds, cache_discovery=False)

def get_drive_folder_id() -> str:
    fid = st.secrets.get("drive_folder_id")
    if not fid:
        raise RuntimeError("`drive_folder_id` missing from secrets.")
    return fid

DRIVE_LIST_KW = dict(supportsAllDrives=True, includeItemsFromAllDrives=True, corpora="allDrives")

def resolve_shortcut(drive, file_id: str) -> str:
    info = drive.files().get(fileId=file_id, fields="id,mimeType,shortcutDetails", supportsAllDrives=True).execute()
    return info["shortcutDetails"]["targetId"] if info.get("mimeType") == "application/vnd.google-apps.shortcut" else file_id

def list_children(drive, parent_id: str, mime_type: Optional[str] = None) -> List[Dict]:
    q = f"'{parent_id}' in parents and trashed=false"
    if mime_type:
        q += f" and mimeType='{mime_type}'"
    files, page_token = [], None
    while True:
        resp = drive.files().list(
            q=q, spaces="drive",
            fields="nextPageToken, files(id,name,mimeType)",
            pageToken=page_token, pageSize=1000, **DRIVE_LIST_KW
        ).execute()
        files.extend(resp.get("files", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return files

def find_child_by_name(drive, parent_id: str, name: str) -> Optional[Dict]:
    q = f"'{parent_id}' in parents and trashed=false and name='{name}'"
    resp = drive.files().list(q=q, spaces="drive", fields="files(id)", pageSize=1, **DRIVE_LIST_KW).execute()
    return resp.get("files", [])[0] if resp.get("files") else None

def create_subfolder(drive, parent_id: str, name: str) -> str:
    meta = {"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [parent_id]}
    return drive.files().create(body=meta, fields="id", supportsAllDrives=True).execute()["id"]

# --- replace the existing download_file() with this ---
def download_file(drive, file_id: str, local_path: str, *, max_attempts: int = 4):
    """
    Robust Google Drive downloader:
      - chunked download with small chunks + retries
      - exponential backoff
      - final fallback: single-shot execute() to avoid chunked TLS issues
    """
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    tmp_path = local_path + ".part"

    # Clean any previous partial
    try:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    except Exception:
        pass

    for attempt in range(1, max_attempts + 1):
        try:
            # Try chunked first
            request = drive.files().get_media(fileId=file_id)
            with io.FileIO(tmp_path, "wb") as fh:
                # smaller chunks reduce TLS flakiness on some networks
                downloader = MediaIoBaseDownload(fh, request, chunksize=256 * 1024)
                done = False
                while not done:
                    # increase retries for transient errors
                    _, done = downloader.next_chunk(num_retries=5)
            os.replace(tmp_path, local_path)
            return  # success
        except Exception as e:
            # Last attempt: fallback to one-shot (in-memory) download
            if attempt == max_attempts:
                try:
                    content = drive.files().get_media(fileId=file_id).execute(num_retries=5)
                    with open(tmp_path, "wb") as fh:
                        fh.write(content)
                    os.replace(tmp_path, local_path)
                    return
                except Exception:
                    # cleanup and re-raise the original error
                    try:
                        if os.path.exists(tmp_path):
                            os.remove(tmp_path)
                    except Exception:
                        pass
                    raise e
            # Backoff before next attempt
            time.sleep(min(2 ** attempt, 10))

def upload_file(drive, parent_id: str, local_path: str):
    name = os.path.basename(local_path)
    media = MediaFileUpload(local_path, resumable=True)
    metadata = {"name": name, "parents": [parent_id]}
    drive.files().create(body=metadata, media_body=media, fields="id", supportsAllDrives=True).execute()

def delete_file_or_folder(drive, file_id: str):
    try:
        drive.files().delete(fileId=file_id, supportsAllDrives=True).execute()
    except HttpError as e:
        if e.resp.status != 404:
            raise e

def ensure_partition_folder(drive, root_id: str, date_str: str) -> str:
    name = f"Date={date_str}"
    found = find_child_by_name(drive, root_id, name)
    return found["id"] if found else create_subfolder(drive, root_id, name)

def local_partition_dir(date_str: str) -> str:
    return os.path.join(LOCAL_CACHE_DIR, f"Date={date_str}")

def list_local_dates() -> Set[str]:
    if not os.path.isdir(LOCAL_CACHE_DIR):
        return set()
    return {n.split("Date=")[-1] for n in os.listdir(LOCAL_CACHE_DIR) if n.startswith("Date=")}

def ensure_local_partitions_for_dates(drive, root_id: str, dates_needed: Set[str]):
    os.makedirs(LOCAL_CACHE_DIR, exist_ok=True)
    if not dates_needed:
        return
    folders_on_drive = {f["name"]: f for f in list_children(drive, root_id, "application/vnd.google-apps.folder")}
    for ds in sorted(list(dates_needed)):
        part_name, local_dir = f"Date={ds}", local_partition_dir(ds)
        if os.path.isdir(local_dir) and os.listdir(local_dir):
            continue
        remote_folder = folders_on_drive.get(part_name)
        if not remote_folder:
            continue
        files_to_download = [
            f for f in list_children(drive, remote_folder["id"])
            if f.get("mimeType") != "application/vnd.google-apps.folder"
        ]
        for f in files_to_download:
            try:
                download_file(drive, f["id"], os.path.join(local_dir, f["name"]))
            except Exception as e:
                # keep going; show a warning for the specific file
                st.warning(f"Could not download **{f.get('name','(unnamed)')}** ({f.get('id')}): {e}")

def upload_new_local_files(drive, root_id: str, dates_affected: Set[str]):
    for ds in dates_affected:
        part_dir = local_partition_dir(ds)
        if not os.path.isdir(part_dir):
            continue
        dest_id = ensure_partition_folder(drive, root_id, ds)
        for fname in os.listdir(part_dir):
            fpath = os.path.join(part_dir, fname)
            if os.path.isfile(fpath):
                upload_file(drive, dest_id, fpath)

def delete_dates_remote_and_local(drive, root_id: str, dates_to_delete: Set[str]):
    folders_on_drive = {f["name"]: f for f in list_children(drive, root_id, "application/vnd.google-apps.folder")}
    for ds in dates_to_delete:
        part_name = f"Date={ds}"
        if (remote_folder := folders_on_drive.get(part_name)):
            for f in list_children(drive, remote_folder["id"]):
                delete_file_or_folder(drive, f["id"])
            delete_file_or_folder(drive, remote_folder["id"])
        local_dir = local_partition_dir(ds)
        if os.path.isdir(local_dir):
            shutil.rmtree(local_dir, ignore_errors=True)

# -------------------------------------------------------------------
# Data manager + parsing
# -------------------------------------------------------------------
class DataMgr:
    def __init__(self, base_path: str):
        self.base = os.path.abspath(base_path)
        os.makedirs(self.base, exist_ok=True)
        self.con = duckdb.connect()

    def _rp(self) -> str:
        return os.path.join(self.base, "*", "*.parquet")

    def get_all_campaigns(self) -> List[str]:
        try:
            return (
                self.con.execute(f"SELECT DISTINCT CAMPAIGN FROM read_parquet('{self._rp()}') ORDER BY 1;")
                .df()["CAMPAIGN"].tolist()
            )
        except Exception:
            return []

    def get_summary(self, d1: str, d2: str, camps: Tuple[str, ...], group_by: List[str], pvals: Tuple[int, ...]) -> pd.DataFrame:
        if not camps or not group_by:
            return pd.DataFrame()
        group_by_str = ", ".join([f'"{c}"' for c in group_by])
        psel = ", ".join([f'ROUND(QUANTILE_CONT(min_dial_speed, {p/100.0}))::INTEGER AS "P{p} DS"' for p in pvals])
        q = f"""
        WITH MinSpeeds AS (
          SELECT {group_by_str}, MIN("Dial Speed (seconds)") AS min_dial_speed
          FROM read_parquet('{self._rp()}', hive_partitioning=1)
          WHERE Date BETWEEN '{d1}' AND '{d2}' AND CAMPAIGN IN {camps}
          GROUP BY {group_by_str}, "Level1"
        )
        SELECT {group_by_str},
               COUNT(min_dial_speed)::INTEGER AS "Call Count",
               ROUND(AVG(min_dial_speed))::INTEGER AS "Avg Dial Speed",
               {psel}
        FROM MinSpeeds
        GROUP BY {group_by_str}
        ORDER BY {group_by_str};
        """
        try:
            return self.con.execute(q).df()
        except Exception:
            return pd.DataFrame()

    def get_weekly_summary(self, d1: str, d2: str, camps: Tuple[str, ...], pvals: Tuple[int, ...]) -> pd.DataFrame:
        if not camps:
            return pd.DataFrame()
        psel = ", ".join([f'ROUND(QUANTILE_CONT(min_dial_speed, {p/100.0}))::INTEGER AS "P{p} DS"' for p in pvals])
        q = f"""
        WITH MinSpeeds AS (
          SELECT DATE_TRUNC('week', Date) AS week_start_date,
                 CAMPAIGN,
                 MIN("Dial Speed (seconds)") AS min_dial_speed
          FROM read_parquet('{self._rp()}', hive_partitioning=1)
          WHERE Date BETWEEN '{d1}' AND '{d2}' AND CAMPAIGN IN {camps}
          GROUP BY week_start_date, CAMPAIGN, "Level1"
        )
        SELECT week_start_date AS "Week Date",
               CAMPAIGN,
               COUNT(min_dial_speed)::INTEGER AS "Call Count",
               ROUND(AVG(min_dial_speed))::INTEGER AS "Avg Dial Speed",
               {psel}
        FROM MinSpeeds
        GROUP BY "Week Date", CAMPAIGN
        ORDER BY "Week Date" DESC, CAMPAIGN;
        """
        try:
            return self.con.execute(q).df()
        except Exception as e:
            st.error(f"Error in weekly summary: {e}")
            return pd.DataFrame()

    def get_overall_stats(self, d1: str, d2: str, camps: Tuple[str, ...], pvals: Tuple[int, ...]) -> Dict[str, int]:
        default_stats = {"Call Count": 0, "Avg Dial Speed": 0, **{f"P{p} DS": 0 for p in pvals}}
        if not camps: return default_stats
        psel = ", ".join([f'ROUND(QUANTILE_CONT(min_dial_speed, {p/100.0}))::INTEGER AS "P{p} DS"' for p in pvals])
        q = f"""
        WITH MinSpeeds AS (
          SELECT MIN("Dial Speed (seconds)") AS min_dial_speed
          FROM read_parquet('{self._rp()}', hive_partitioning=1)
          WHERE Date BETWEEN '{d1}' AND '{d2}' AND CAMPAIGN IN {camps}
          GROUP BY "Level1"
        )
        SELECT COUNT(min_dial_speed)::INTEGER AS "Call Count",
               ROUND(AVG(min_dial_speed))::INTEGER AS "Avg Dial Speed",
               {psel}
        FROM MinSpeeds;
        """
        try:
            recs = self.con.execute(q).df().to_dict("records")
            return recs[0] if recs else default_stats
        except Exception:
            return default_stats

    def write_partitioned_parquet(self, df: pd.DataFrame) -> Set[str]:
        if df.empty: return set()
        df["Date"] = pd.to_datetime(df["Insert_Dt"], errors="coerce").dt.date
        df.dropna(subset=["Date"], inplace=True)
        touched = set()
        for ds, g in df.groupby(df["Date"].astype(str)):
            part_dir = local_partition_dir(ds)
            os.makedirs(part_dir, exist_ok=True)
            fname = f"import_{int(time.time())}_{len(os.listdir(part_dir)) + 1}.parquet"
            g.to_parquet(os.path.join(part_dir, fname), index=False)
            touched.add(str(ds))
        return touched

@st.cache_resource(show_spinner=False)
def get_dm() -> "DataMgr":
    return DataMgr(LOCAL_CACHE_DIR)

def parse_and_filter_df(df: pd.DataFrame) -> pd.DataFrame:
    req = ["CAMPAIGNNAME", "Level1", "CallStartdate", "Insert_Dt", "attempt", "CallStatus"]
    miss = [c for c in req if c not in df.columns]
    if miss: raise ValueError("Missing required columns: " + ", ".join(miss))

    df = df.copy()
    df.dropna(subset=["Level1"], inplace=True)
    df["Level1"] = df["Level1"].astype(str).str.strip()
    df = df[df["Level1"] != ""]
    if df.empty: return df

    df["attempt"] = pd.to_numeric(df["attempt"], errors="coerce").fillna(0).astype(int)
    df["CallStatus"] = df["CallStatus"].astype(str).str.strip()
    df = df[(df["attempt"] == 1) & (df["CallStatus"] == "Connected")].copy()
    if df.empty: return df

    df.rename(columns={"CAMPAIGNNAME": "CAMPAIGN"}, inplace=True)
    df["Dial Speed (seconds)"] = (
        pd.to_datetime(df["CallStartdate"], dayfirst=True, errors="coerce")
        - pd.to_datetime(df["Insert_Dt"], dayfirst=True, errors="coerce")
    ).dt.total_seconds().abs()
    df["Interval"] = pd.to_datetime(df["Insert_Dt"], errors="coerce").dt.hour
    df["Insert_Dt"] = pd.to_datetime(df["Insert_Dt"], errors="coerce")
    return df

# -------------------------------------------------------------------
# UI helpers
# -------------------------------------------------------------------
def today_ist() -> date:
    return datetime.now(ASIA_KOLKATA).date()

def first_of_month_ist(d: date) -> date:
    return d.replace(day=1)

def render_cards(stats: Dict[str, int], percentiles: Tuple[int, ...]):
    icons = {
        "Call Count": "📞",
        "Avg Dial Speed": "⏱️",
        f"P{percentiles[0]} DS": "📈",
        f"P{percentiles[1]} DS": "📊",
        f"P{percentiles[2]} DS": "📉",
    }
    keys = ["Call Count", "Avg Dial Speed", f"P{percentiles[0]} DS", f"P{percentiles[1]} DS", f"P{percentiles[2]} DS"]
    cols = st.columns(len(keys))
    for i, k in enumerate(keys):
        with cols[i]:
            v = stats.get(k, 0) or 0
            cls = f"metric-card mc-{i % 5}"
            html = f'<div class="{cls}"><div class="metric-title">{icons.get(k,"🔹")} {k}</div><div class="metric-value">{int(v)}</div></div>'
            st.markdown(html, unsafe_allow_html=True)

# -------------------------------------------------------------------
# Main after login
# -------------------------------------------------------------------
try:
    drive = get_drive_service()
    root_folder_id = resolve_shortcut(drive, get_drive_folder_id())
    dm = get_dm()
except Exception as e:
    st.error(f"A critical error occurred during initialization: {e}")
    st.stop()

with st.sidebar:
    role_badge = "🛡️ Admin" if IS_ADMIN else "👤 User"
    st.markdown(f"**Welcome, {user.get('name','User')}!**  \n{role_badge}")
    if st.button("Log out"):
        st.session_state.clear()
        st.rerun()
    st.divider()
    st.header("🔍 Filters")

    preset = st.selectbox(
        "Date Range Preset",
        ["This Month", "Last 4 Weeks", "Last 2 Weeks", "Previous Month", "Last 7 Days", "Last 30 Days", "Last 60 Days", "Custom..."],
        index=0,
    )
    t = today_ist()
    if preset == "This Month":
        d1, d2 = first_of_month_ist(t), t
    elif preset == "Last 4 Weeks":
        d1, d2 = t - timedelta(days=27), t
    elif preset == "Last 2 Weeks":
        d1, d2 = t - timedelta(days=13), t
    elif preset == "Previous Month":
        first_this = first_of_month_ist(t); prev_last = first_this - timedelta(days=1)
        d1, d2 = prev_last.replace(day=1), prev_last
    elif preset == "Last 7 Days":
        d1, d2 = t - timedelta(days=6), t
    elif preset == "Last 30 Days":
        d1, d2 = t - timedelta(days=29), t
    elif preset == "Last 60 Days":
        d1, d2 = t - timedelta(days=59), t
    else:
        d1, d2 = t - timedelta(days=29), t

    if d1 > d2: d1, d2 = d2, d1
    d1_sel = st.date_input("From (IST)", value=d1, min_value=date(2000, 1, 1), max_value=t)
    d2_sel = st.date_input("To (IST)", value=d2, min_value=date(2000, 1, 1), max_value=t)
    d1, d2 = (d2_sel, d1_sel) if d1_sel > d2_sel else (d1_sel, d2_sel)

    all_needed_dates = {d.strftime(DATE_FMT_QUERY) for d in pd.date_range(d1, d2, freq="D")}
    missing_dates = all_needed_dates - list_local_dates()
    if missing_dates:
        with st.spinner(f"Syncing {len(missing_dates)} date partition(s) from Database Server..."):
            ensure_local_partitions_for_dates(drive, root_folder_id, missing_dates)

    all_campaigns = dm.get_all_campaigns()
    if "selected_campaigns" not in st.session_state:
        st.session_state.selected_campaigns = [c for c in all_campaigns if c not in UNRECOMMENDED_CAMPAIGNS]
    st.write("**Campaigns**")
    c1, c2, c3 = st.columns(3)
    if c1.button("Recommended", use_container_width=True):
        st.session_state.selected_campaigns = [c for c in all_campaigns if c not in UNRECOMMENDED_CAMPAIGNS]; st.rerun()
    if c2.button("All", use_container_width=True):
        st.session_state.selected_campaigns = list(all_campaigns); st.rerun()
    if c3.button("None", use_container_width=True):
        st.session_state.selected_campaigns = []; st.rerun()
    selected = st.multiselect("Selected Campaigns", options=all_campaigns, default=st.session_state.selected_campaigns, label_visibility="collapsed")
    st.session_state.selected_campaigns = selected

    st.divider()
    st.header("⚙️ Settings")
    st.caption("Percentiles")
    c1, c2, c3 = st.columns(3)
    p0 = c1.number_input("P1", 50, 99, DEFAULT_PERCENTILES[0], 1, label_visibility="collapsed")
    p1 = c2.number_input("P2", 50, 99, DEFAULT_PERCENTILES[1], 1, label_visibility="collapsed")
    p2 = c3.number_input("P3", 50, 99, DEFAULT_PERCENTILES[2], 1, label_visibility="collapsed")
    percentiles = tuple(sorted({int(p0), int(p1), int(p2)}, reverse=True))
    st.divider()
    st.markdown("**☁️ Database Server**")
    st.success("Connected")
    st.markdown('<div class="sidebar-help">Data is organized by the database date partitions like <code>Date=YYYY-MM-DD/</code>.</div>', unsafe_allow_html=True)

st.title("📞 Dial Speed Analyzer")
# Build tab list by role
tab_options = ["Dashboard", "Import Data", "Manage Data"] if IS_ADMIN else ["Dashboard"]
tab_icons   = ["clipboard-data", "cloud-arrow-up", "trash3"] if IS_ADMIN else ["clipboard-data"]

selected_tab = option_menu(
    menu_title=None,
    options=tab_options,
    icons=tab_icons,
    menu_icon="cast",
    default_index=0,
    orientation="horizontal",
)

if selected_tab == "Dashboard":
    if not st.session_state.selected_campaigns:
        st.info("⬅️ Please select at least one campaign from the sidebar to view the dashboard.")
    else:
        d1q, d2q = d1.strftime(DATE_FMT_QUERY), d2.strftime(DATE_FMT_QUERY)

        @st.cache_data(show_spinner="Running analytics...")
        def compute_all(d1q, d2q, camps, pvals):
            summary_by_camp = dm.get_summary(d1q, d2q, camps, ["CAMPAIGN"], pvals)
            summary_by_date = dm.get_summary(d1q, d2q, camps, ["Date"], pvals)
            weekly_summary = dm.get_weekly_summary(d1q, d2q, camps, pvals)
            by_interval = dm.get_summary(d1q, d2q, camps, ["Interval"], pvals)
            dashboard = dm.get_summary(d1q, d2q, camps, ["Date", "Interval", "CAMPAIGN"], pvals)

            if not summary_by_date.empty: summary_by_date.sort_values(by="Date", ascending=False, inplace=True)
            if not by_interval.empty: by_interval.sort_values(by="Interval", ascending=True, inplace=True)
            if not dashboard.empty: dashboard.sort_values(by=["Date", "Interval"], ascending=[False, True], inplace=True)

            stats = dm.get_overall_stats(d1q, d2q, camps, pvals)
            return summary_by_camp, summary_by_date, weekly_summary, by_interval, dashboard, stats

        by_camp, by_date, by_week, by_interval, dashboard, stats = compute_all(
            d1q, d2q, tuple(st.session_state.selected_campaigns), percentiles
        )

        render_cards(stats, percentiles)
        st.markdown("<br>", unsafe_allow_html=True)

        tabs = st.tabs(["Overall Dashboard", "By Campaign", "By Date", "Weekly View", "By Interval"])
        date_column_config = st.column_config.DatetimeColumn("Date", format="DD-MMM-YY")
        week_date_column_config = st.column_config.DatetimeColumn("Week Date", format="DD-MMM-YY")

        with tabs[0]:
            st.dataframe(dashboard, use_container_width=True, hide_index=True, column_config={"Date": date_column_config})
        with tabs[1]:
            st.dataframe(by_camp, use_container_width=True, hide_index=True)
        with tabs[2]:
            st.dataframe(by_date, use_container_width=True, hide_index=True, column_config={"Date": date_column_config})
        with tabs[3]:
            st.dataframe(by_week, use_container_width=True, hide_index=True, column_config={"Week Date": week_date_column_config})
        with tabs[4]:
            st.dataframe(by_interval, use_container_width=True, hide_index=True)

elif selected_tab == "Import Data":
    if not IS_ADMIN: st.stop()
    st.header("📥 Import Data")
    st.info("Required columns: `CAMPAIGNNAME`, `Level1`, `CallStartdate`, `Insert_Dt`, `attempt`, `CallStatus`")

    uploaded_files = st.file_uploader("Select one or more CSV or Excel files", accept_multiple_files=True, type=["csv", "xls", "xlsx"])
    if st.button("Process & Import Files", type="primary", disabled=(not uploaded_files), use_container_width=True):
        total_rows, dfs = 0, []
        progress_bar = st.progress(0, "Starting import...")
        for i, f in enumerate(uploaded_files):
            try:
                progress_bar.progress((i + 1) / len(uploaded_files), f"Processing {f.name}...")
                df = pd.read_csv(f) if f.name.lower().endswith(".csv") else pd.read_excel(f)
                df_filtered = parse_and_filter_df(df)
                if not df_filtered.empty:
                    total_rows += len(df_filtered)
                    dfs.append(df_filtered)
            except Exception as e:
                st.warning(f"Could not process {f.name}: {e}")

        progress_bar.progress(1.0, "Finalizing...")
        if not dfs:
            st.warning("No valid data found to import after filtering.")
        else:
            merged = pd.concat(dfs, ignore_index=True)
            touched = dm.write_partitioned_parquet(merged)
            try:
                with st.spinner(f"Uploading {len(touched)} date partition(s) to Database..."):
                    upload_new_local_files(drive, root_folder_id, touched)
                st.success(f"Successfully imported {total_rows:,} rows across {len(touched)} date partition(s).")
                st.balloons()
                compute_all.clear()
            except Exception as e:
                st.error(f"Data was imported locally, but the upload to Database failed: {e}")
        progress_bar.empty()

elif selected_tab == "Manage Data":
    if not IS_ADMIN: st.stop()
    st.header("🧹 Manage Stored Data")
    st.warning("**Warning:** Deleting dates will permanently remove the data from both the local cache and Database Server.", icon="⚠️")

    dates_local = sorted(list_local_dates())
    if not dates_local:
        st.info("No data partitions found. Import data to get started.")
    else:
        months = sorted({d[:7] for d in dates_local})
        sel_months = st.multiselect("Filter by month (YYYY-MM)", options=months)

        preselect = [d for d in dates_local if not sel_months or d[:7] in sel_months]
        sel_dates = st.multiselect("Select date partitions to delete", options=preselect)
        if st.button("Delete Selected Dates", type="primary", disabled=(not sel_dates), use_container_width=True):
            try:
                with st.spinner(f"Deleting {len(sel_dates)} date partition(s)..."):
                    delete_dates_remote_and_local(drive, root_folder_id, set(sel_dates))
                st.success(f"Successfully deleted {len(sel_dates)} date partition(s).")
                st.rerun()
            except Exception as e:
                st.error(f"An error occurred during deletion: {e}")

st.markdown("</div>", unsafe_allow_html=True)
