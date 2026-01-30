# app.py
# pip install streamlit gspread google-auth pandas requests

import re
from datetime import datetime
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import pandas as pd
import requests
import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
import os, json

YT_API_KEY = os.getenv("YT_API_KEY", "").strip()

GCP_SERVICE_ACCOUNT_JSON = os.getenv("GCP_SERVICE_ACCOUNT_JSON", "").strip()
if not GCP_SERVICE_ACCOUNT_JSON:
    raise RuntimeError("Missing GCP_SERVICE_ACCOUNT_JSON in Render environment secrets")

SERVICE_ACCOUNT_INFO = json.loads(GCP_SERVICE_ACCOUNT_JSON)

# =========================
# CONFIG
# =========================
SPREADSHEET_ID = "19-gJ3_qbKl7jYomoX00riJoi5Qcbf0qB707ZXcOWG9I"

FB_SHEET_NAME = "Final_FB"
YT_SHEET_NAME = "Final_YT"

SUBMITTED_BY_COL = "Submitted by"
DATE_SUBMITTED_COL = "date submitted"  # if missing, we create it

AFFILIATION_OPTIONS = ["AL", "BNP", "JI", "NCP", "Others", "RA", "FM", "Foreign", "Influencers"]

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

# =========================
# URL NORMALIZATION — Facebook
# =========================
def normalize_facebook_url(raw: str) -> str:
    if raw is None:
        return ""
    s = raw.strip()
    s = re.sub(r"\s+", "", s)
    if not s:
        return ""

    # If user pasted something like "https://https://..."
    s = re.sub(r"^(https?://)+", "https://", s, flags=re.I)

    if not re.match(r"^https?://", s, flags=re.I):
        s = "https://" + s

    try:
        p = urlparse(s)
    except Exception:
        return ""

    host = (p.netloc or "").lower()

    # normalize facebook hosts
    if host in {"facebook.com", "m.facebook.com", "web.facebook.com", "www.facebook.com", "fb.com"} or host.endswith(".facebook.com"):
        host = "www.facebook.com"

    path = p.path or ""
    if path != "/":
        path = path.rstrip("/")

    q = dict(parse_qsl(p.query, keep_blank_values=True))

    # Keep only profile.php?id=...
    query = ""
    if path.lower() in ("/profile.php", "profile.php"):
        keep = {}
        if "id" in q:
            keep["id"] = q["id"]
        query = urlencode(keep, doseq=True)

        # normalize exact path
        path = "/profile.php"

    return urlunparse(("https", host, path, "", query, ""))


# =========================
# URL NORMALIZATION — YouTube
# =========================
def normalize_youtube_url(raw: str) -> str:
    if raw is None:
        return ""
    s = raw.strip()
    s = re.sub(r"\s+", "", s)
    if not s:
        return ""

    if not re.match(r"^https?://", s, flags=re.I):
        s = "https://" + s

    try:
        p = urlparse(s)
    except Exception:
        return ""

    host = (p.netloc or "").lower()

    # canonicalize common youtube hosts
    if host in {"youtube.com", "m.youtube.com", "www.youtube.com"} or host.endswith(".youtube.com"):
        host = "www.youtube.com"
    elif host in {"youtu.be", "www.youtu.be"}:
        host = "youtu.be"

    path = p.path or ""
    if path != "/":
        path = path.rstrip("/")

    # drop query + fragment entirely
    return urlunparse(("https", host, path, "", "", ""))


def extract_youtube_identifier(norm_url: str):
    """
    Returns tuple (kind, value)
      kind:
        - "channel_id" : value = UC...
        - "handle"     : value = NotunShomoy (without @)
        - "user"       : value = Username
        - "custom"     : value = CustomName
        - None         : unknown
    Accepts extra subpaths like /videos, /featured, etc.
    """
    if not norm_url:
        return (None, None)

    p = urlparse(norm_url)
    host = (p.netloc or "").lower()
    path = p.path or ""

    if host.endswith("youtu.be"):
        return (None, None)

    # /@handle or /@handle/...
    m = re.match(r"^/@([^/]+)(?:/.*)?$", path)
    if m:
        return ("handle", m.group(1))

    # /channel/UCxxxx or /channel/UCxxxx/...
    m = re.match(r"^/channel/(UC[a-zA-Z0-9_-]{10,})(?:/.*)?$", path, flags=re.I)
    if m:
        return ("channel_id", m.group(1))

    # /user/Username or /user/Username/...
    m = re.match(r"^/user/([^/]+)(?:/.*)?$", path, flags=re.I)
    if m:
        return ("user", m.group(1))

    # /c/CustomName or /c/CustomName/...
    m = re.match(r"^/c/([^/]+)(?:/.*)?$", path, flags=re.I)
    if m:
        return ("custom", m.group(1))

    # fallback: /Something (treat as custom)
    m = re.match(r"^/([^/]+)(?:/.*)?$", path)
    if m and m.group(1) and not m.group(1).startswith("@"):
        return ("custom", m.group(1))

    return (None, None)


# =========================
# YouTube Data API helpers
# =========================
def normalize_youtube_handle_url(url: str) -> str:
    """
    If url is a channel handle url, return canonical lowercased form:
    https://www.youtube.com/@handle
    Otherwise return normalized youtube url.
    """
    u = normalize_youtube_url(url)
    kind, val = extract_youtube_identifier(u)
    if kind == "handle" and val:
        return f"https://www.youtube.com/@{val.strip().lstrip('@').lower()}"
    return u

def _yt_key():
    if "YT_API_KEY" not in st.secrets:
        raise RuntimeError("Missing YT_API_KEY in Streamlit secrets.")
    return str(st.secrets["YT_API_KEY"]).strip()


def yt_search_channel_id(query: str) -> str:
    """
    Best-effort: search channels by query string and return top channelId.
    """
    key = _yt_key()
    url = "https://www.googleapis.com/youtube/v3/search"
    params = {
        "part": "snippet",
        "type": "channel",
        "maxResults": 1,
        "q": query,
        "key": key,
    }
    r = requests.get(url, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    items = data.get("items", [])
    if not items:
        return ""
    ch_id = items[0].get("snippet", {}).get("channelId") or items[0].get("id", {}).get("channelId") or ""
    return ch_id

def yt_channel_id_from_handle_page(handle: str) -> str:
    # Use the canonical channel page
    url = f"https://www.youtube.com/@{handle}"
    r = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
    if r.status_code != 200:
        return ""

    html = r.text

    # Common patterns in YouTube HTML
    # 1) "channelId":"UCxxxx"
    m = re.search(r'"channelId":"(UC[a-zA-Z0-9_-]{10,})"', html)
    if m:
        return m.group(1)

    # 2) externalId":"UCxxxx"
    m = re.search(r'"externalId":"(UC[a-zA-Z0-9_-]{10,})"', html)
    if m:
        return m.group(1)

    return ""

def yt_channel_id_from_input(norm_url: str) -> str:
    """
    Quota-aware resolver:
    - /channel/UC...  -> parse from URL (no API)
    - /@handle        -> HTML parse (free). If it fails, return "" (do NOT search).
    - /user/...       -> channels.list(forUsername) first, then search.list fallback
    - /c/...          -> search.list
    """
    kind, val = extract_youtube_identifier(norm_url)

    if kind == "channel_id" and val:
        return val

    if kind == "handle" and val:
        handle = val.strip().lstrip("@").lower()
        return yt_channel_id_from_handle_page(handle) or ""

    if kind == "user" and val:
        # Try legacy forUsername first (cheap). If it fails, search (allowed for /user).
        key = _yt_key()
        url = "https://www.googleapis.com/youtube/v3/channels"
        params = {"part": "id", "forUsername": val, "key": key}
        r = requests.get(url, params=params, timeout=20)
        r.raise_for_status()
        items = r.json().get("items", [])
        if items:
            return items[0].get("id", "") or ""
        return yt_search_channel_id(val)

    if kind == "custom" and val:
        # Only for /c/... or ambiguous custom URLs
        return yt_search_channel_id(val)

    return ""


def yt_channel_exists(channel_id: str) -> bool:
    """Cheap existence check using channels.list(part=id)."""
    if not channel_id:
        return False
    key = _yt_key()
    url = "https://www.googleapis.com/youtube/v3/channels"
    params = {"part": "id", "id": channel_id, "key": key}
    r = requests.get(url, params=params, timeout=20)
    r.raise_for_status()
    items = r.json().get("items", [])
    return bool(items)


def yt_fetch_channel_details(channel_id: str) -> dict:
    """
    Fetch joined date, subscriber, location, totals.
    """
    if not channel_id:
        return {}

    key = _yt_key()
    url = "https://www.googleapis.com/youtube/v3/channels"
    params = {
        "part": "snippet,statistics",
        "id": channel_id,
        "key": key,
    }
    r = requests.get(url, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    items = data.get("items", [])
    if not items:
        return {}

    it = items[0]
    snippet = it.get("snippet", {}) or {}
    stats = it.get("statistics", {}) or {}

    joined_full = snippet.get("publishedAt", "")  # ISO datetime
    joined = joined_full[:10] if joined_full else ""
    country = snippet.get("country", "")

    # subscriberCount can be absent if hidden
    subs = stats.get("subscriberCount", "")
    vids = stats.get("videoCount", "")
    views = stats.get("viewCount", "")

    return {
        "Channel Joined Date": joined,
        "Subscriber": subs,
        "Channel Location": country,
        "Channel Total Videos": vids,
        "Channel Total Views": views,
    }


def yt_canonical_actor_link(norm_url: str, channel_id: str) -> str:
    """
    Keep @handle if provided; otherwise store channel URL.
    """
    kind, val = extract_youtube_identifier(norm_url)
    if kind == "handle" and val:
        return f"https://www.youtube.com/@{val}"
    if channel_id:
        return f"https://www.youtube.com/channel/{channel_id}"
    return norm_url or ""


# =========================
# GOOGLE SHEETS HELPERS
# =========================
def get_gspread_client():
    if "gcp_service_account" in st.secrets:
        info = dict(st.secrets["gcp_service_account"])
    elif "gcp_service_account_json" in st.secrets:
        import json
        info = json.loads(st.secrets["gcp_service_account_json"])
    else:
        raise RuntimeError(
            "Missing service account in Streamlit secrets. "
            "Add [gcp_service_account] or gcp_service_account_json."
        )

    creds = Credentials.from_service_account_info(info, scopes=SCOPES)
    return gspread.authorize(creds)


def open_worksheet(gc, worksheet_name: str):
    sh = gc.open_by_key(SPREADSHEET_ID)
    return sh.worksheet(worksheet_name)


def _lower_map(headers):
    return {str(h).strip().lower(): idx for idx, h in enumerate(headers)}


def ensure_headers(ws, must_have_headers):
    headers = ws.row_values(1) or []
    lm = _lower_map(headers)

    missing = []
    for h in must_have_headers:
        if h.strip().lower() not in lm:
            missing.append(h)

    if missing:
        new_headers = headers + missing
        ws.update("1:1", [new_headers])
        headers = new_headers

    return headers


@st.cache_data(ttl=60, show_spinner=False)
def load_db(sheet_name: str, platform: str):
    gc = get_gspread_client()
    ws = open_worksheet(gc, sheet_name)

    if platform == "Facebook":
        must_have = ["actor_name", "actor_link", "affiliation", "followers", "evidence", SUBMITTED_BY_COL, DATE_SUBMITTED_COL]
    else:
        must_have = [
            "actor_name", "actor_link", "affiliation", "evidence",
            "Channel ID", "TAG", "Comment",
            "Channel Joined Date", "Subscriber", "Channel Location", "Channel Total Videos", "Channel Total Views",
            SUBMITTED_BY_COL, DATE_SUBMITTED_COL
        ]

    headers = ensure_headers(ws, must_have)
    values = ws.get_all_values()

    if len(values) <= 1:
        return pd.DataFrame(columns=headers)

    df = pd.DataFrame(values[1:], columns=headers)

    # Normalize actor_link for FB matching
    if platform == "Facebook":
        actor_link_col = next((c for c in df.columns if c.strip().lower() == "actor_link"), None)
        if actor_link_col:
            df[actor_link_col] = df[actor_link_col].astype(str).map(normalize_facebook_url)

    return df


def append_submission(sheet_name: str, platform: str, row_dict: dict):
    gc = get_gspread_client()
    ws = open_worksheet(gc, sheet_name)

    if platform == "Facebook":
        must_have = ["actor_name", "actor_link", "affiliation", "followers", "evidence", SUBMITTED_BY_COL, DATE_SUBMITTED_COL]
    else:
        must_have = [
            "actor_name", "actor_link", "affiliation", "evidence",
            "Channel ID", "TAG", "Comment",
            "Channel Joined Date", "Subscriber", "Channel Location", "Channel Total Videos", "Channel Total Views",
            SUBMITTED_BY_COL, DATE_SUBMITTED_COL
        ]

    headers = ensure_headers(ws, must_have)
    lm = _lower_map(headers)

    out_row = [""] * len(headers)
    for k, v in row_dict.items():
        lk = str(k).strip().lower()
        if lk in lm:
            out_row[lm[lk]] = v

    ws.append_row(out_row, value_input_option="USER_ENTERED")


# =========================
# UI
# =========================
st.set_page_config(page_title="Actor Database — FB + YT", layout="wide")

# ---- Centered, professional width + sticky right panel ----
st.markdown(
    """
    <style>
    /* Center the main content and limit width */
    .block-container {
        max-width: 1120px;              /* a bit wider to support 2-col layout */
        padding-left: 2rem;
        padding-right: 2rem;
        margin-left: auto;
        margin-right: auto;
    }
    /* Slightly tighten vertical spacing */
    .block-container > div {
        padding-top: 1.25rem;
    }

    /* Card styles */
    .card {
        background: #f8f9fa;
        border: 1px solid #e6e6e6;
        border-radius: 10px;
        padding: 1.1rem 1.2rem;
    }
    .card h4 { margin: 0 0 0.5rem 0; }
    .card h5 { margin: 0.9rem 0 0.4rem 0; }
    .muted { color: #666; font-size: 0.92rem; }

    /* Sticky info panel */
    .sticky {
        position: sticky;
        top: 1rem;
    }

    /* Small pill badge */
    .pill {
        display: inline-block;
        padding: 0.18rem 0.55rem;
        border-radius: 999px;
        border: 1px solid #e6e6e6;
        background: #ffffff;
        font-size: 0.85rem;
        color: #444;
        margin-left: 0.5rem;
        vertical-align: middle;
    }

    /* Checklist look */
    .checklist li { margin-bottom: 0.25rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---- Cleaner header ----
st.markdown(
    "## Actor Submission Form\n"
    "<span class='muted'>Facebook & YouTube</span>",
    unsafe_allow_html=True,
)

# ---- Two-column workspace: main app left, guidelines right ----
main_col, info_col = st.columns([3, 2], gap="large")

with main_col:
    platform = st.selectbox("Select platform", ["Facebook", "YouTube"], key="platform_select")

    # Session state for the “not found -> show form” flow (per platform)
    if "pending_add" not in st.session_state:
        st.session_state.pending_add = False
    if "pending_key" not in st.session_state:
        st.session_state.pending_key = ""  # FB: normalized actor_link, YT: channel_id
    if "pending_norm" not in st.session_state:
        st.session_state.pending_norm = ""  # normalized URL to prefill actor_link

    sheet_name = FB_SHEET_NAME if platform == "Facebook" else YT_SHEET_NAME
    db = load_db(sheet_name, platform)

    # ---- Main input row ----
    colA, colB = st.columns([2, 1], gap="large")

    with colA:
        raw_input = st.text_input(
            "Paste actor URL to check",
            placeholder=("https://web.facebook.com/..." if platform == "Facebook" else "youtube.com/@handle or youtube.com/channel/UC..."),
            key="url_input",
        )

        if platform == "Facebook":
            norm = normalize_facebook_url(raw_input)
            st.caption(f"Normalized: `{norm or ''}`")
        else:
            norm = normalize_youtube_url(raw_input)
            st.caption(f"Normalized: `{norm or ''}`")

        check = st.button("Check database", type="primary")

    with colB:
        # Align the metric visually with the input field
        st.markdown("<div style='height: 2.2rem'></div>", unsafe_allow_html=True)
        st.metric("Rows in selected database", len(db))

    st.divider()

    def _find_col(df: pd.DataFrame, target: str):
        t = target.strip().lower()
        for c in df.columns:
            if c.strip().lower() == t:
                return c
        return None

    if check:
        if not norm:
            st.warning("Please paste a valid URL.")
            st.stop()

        if platform == "Facebook":
            if "facebook.com" not in norm:
                st.warning("That doesn't look like a Facebook URL after normalization.")
                st.stop()

            actor_link_col = _find_col(db, "actor_link")
            if not actor_link_col:
                st.error("Sheet must contain `actor_link` column.")
                st.stop()

            matches = db[db[actor_link_col] == norm]
            if not matches.empty:
                st.session_state.pending_add = False
                st.session_state.pending_key = ""
                st.session_state.pending_norm = ""
                st.success("✅ This actor is already in the database.")
                st.dataframe(matches, use_container_width=True)
            else:
                st.session_state.pending_add = True
                st.session_state.pending_key = norm
                st.session_state.pending_norm = norm
                st.error("❌ Not found in database.")
                st.info("Submit it below to add a new row.")

        else:
            if "youtube.com" not in norm and "youtu.be" not in norm:
                st.warning("That doesn't look like a YouTube URL.")
                st.stop()

            ch_id_col = _find_col(db, "Channel ID")
            if not ch_id_col:
                st.error("Sheet must contain `Channel ID` column.")
                st.stop()

            actor_link_col = _find_col(db, "actor_link")
            if not actor_link_col:
                st.error("Sheet must contain `actor_link` column.")
                st.stop()

            # ---------------------------------------
            # 1) FIRST: match by actor_link (NO API)
            # ---------------------------------------
            target_handle = normalize_youtube_handle_url(norm)
            db_handles = db[actor_link_col].astype(str).map(normalize_youtube_handle_url)
            matches = db[db_handles == target_handle]

            # ---------------------------------------
            # 2) If not found: resolve Channel ID with minimal quota
            #    - /channel/UC... -> parse (no API)
            #    - /@handle       -> HTML parse (free) then channels.list(part=id)
            #    - /c or /user    -> API (search allowed only for these)
            # ---------------------------------------
            channel_id = ""
            kind, val = extract_youtube_identifier(norm)

            if matches.empty:
                if kind == "channel_id" and val:
                    channel_id = val

                elif kind == "handle" and val:
                    handle = val.strip().lstrip("@").lower()
                    channel_id = yt_channel_id_from_handle_page(handle) or ""
                    if channel_id and (not yt_channel_exists(channel_id)):
                        channel_id = ""

                elif kind in ("custom", "user"):
                    with st.spinner("Resolving Channel ID via YouTube API..."):
                        channel_id = yt_channel_id_from_input(norm)

                else:
                    channel_id = ""

                if channel_id:
                    channel_id_clean = str(channel_id).strip()
                    matches = db[db[ch_id_col].astype(str).str.strip() == channel_id_clean]

            with st.expander("log", expanded=False):
                st.write("Normalized URL:", norm)
                st.write("Extracted kind/value:", (kind, val))
                st.write("actor_link target:", target_handle)
                st.write("Resolved channel_id:", channel_id or "<skipped/empty>")

            if not matches.empty:
                st.session_state.pending_add = False
                st.session_state.pending_key = ""
                st.session_state.pending_norm = ""
                st.success("✅ This actor is already in the database.")
                st.dataframe(matches, use_container_width=True)
            else:
                st.session_state.pending_add = True
                st.session_state.pending_key = str(channel_id).strip() if channel_id else ""
                st.session_state.pending_norm = norm
                st.error("❌ Not found in database.")
                st.info("Submit it below to add a new row.")

    # =========================
    # Submission Form (shows after "not found")
    # =========================
    if st.session_state.pending_add:
        st.subheader("Add actor to database")

        # --- Optional pre-submit checklist (UI only) ---
        if platform == "Facebook":
            st.markdown(
                """
                <div class="card">
                  <h4 style="margin:0">Submission checklist <span class="pill">Facebook</span></h4>
                  <ul class="checklist">
                    <li>Actor must have <b>≥ 5,000 followers</b>.</li>
                    <li>Add evidence (why this actor matters / context / source).</li>
                    <li><b>FM</b>=Financially Motivated | <b>RA</b>=Religious Actors</li>
                  </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
                <div class="card">
                  <h4 style="margin:0">Submission checklist <span class="pill">YouTube</span></h4>
                  <ul class="checklist">
                    <li>Prefer <b>@handle</b> or <b>/channel/UC...</b> URLs.</li>
                    <li>Add evidence (why this channel matters / context / source).</li>
                    <li><b>FM</b>=Financially Motivated | <b>RA</b>=Religious Actors</li>
                  </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height:0.75rem'></div>", unsafe_allow_html=True)

        with st.form("submit_form", clear_on_submit=True):
            actor_name = st.text_input("actor_name")

            if platform == "Facebook":
                actor_link = st.text_input("actor_link", value=st.session_state.pending_norm)
            else:
                # We'll store canonical @handle if user used it; else channel URL.
                actor_link = st.text_input("actor_link", value=st.session_state.pending_norm)

            affiliation = st.selectbox("affiliation", AFFILIATION_OPTIONS)
            evidence = st.text_area("evidence", height=120)
            # Facebook only field
            followers = ""
            if platform == "Facebook":
                followers = st.text_input("followers")
                
            submitted_by = st.text_input("Submitted by")

            submitted = st.form_submit_button("Submit to database")

        if submitted:
            submitted_time_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

            # Clear cache before checking latest and writing
            st.cache_data.clear()

            latest = load_db(sheet_name, platform)

            if platform == "Facebook":
                actor_link_clean = normalize_facebook_url(actor_link)
                if not actor_link_clean:
                    st.error("actor_link is invalid.")
                    st.stop()
                    if platform == "Facebook":
                        actor_link_clean = normalize_facebook_url(actor_link)

                        # SAFETY NET: remove accidental double protocol
                        actor_link_clean = re.sub(
                            r"^(https?://)+",
                            "https://",
                            actor_link_clean,
                            flags=re.I,
                        )

                        if not actor_link_clean:
                            st.error("actor_link is invalid.")
                            st.stop()

                actor_link_col = _find_col(latest, "actor_link")
                latest_links = set(latest[actor_link_col].dropna().astype(str).tolist()) if actor_link_col else set()

                if actor_link_clean in latest_links:
                    st.warning("Someone added this link just now — it already exists.")
                    st.dataframe(latest[latest[actor_link_col] == actor_link_clean], use_container_width=True)
                    st.stop()

                row = {
                    "actor_name": actor_name.strip(),
                    "actor_link": actor_link_clean,
                    "affiliation": affiliation.strip(),
                    "followers": followers.strip(),
                    "evidence": evidence.strip(),
                    SUBMITTED_BY_COL: submitted_by.strip(),
                    DATE_SUBMITTED_COL: submitted_time_utc,
                }

                append_submission(sheet_name, platform, row)
                st.success("✅ Submitted and appended to the spreadsheet.")
                st.session_state.pending_add = False
                st.session_state.pending_key = ""
                st.session_state.pending_norm = ""
                st.cache_data.clear()
                st.dataframe(load_db(sheet_name, platform).tail(10), use_container_width=True)

            else:
                # Resolve Channel ID (may be empty if we avoided API during "check")
                channel_id = str(st.session_state.pending_key).strip()

                if not channel_id:
                    actor_link_norm0 = normalize_youtube_url(actor_link)
                    kind0, val0 = extract_youtube_identifier(actor_link_norm0)

                    if kind0 == "channel_id" and val0:
                        channel_id = val0

                    elif kind0 == "handle" and val0:
                        handle0 = val0.strip().lstrip("@").lower()
                        channel_id = yt_channel_id_from_handle_page(handle0) or ""
                        if channel_id and (not yt_channel_exists(channel_id)):
                            channel_id = ""

                    elif kind0 in ("custom", "user"):
                        with st.spinner("Resolving Channel ID via YouTube API..."):
                            channel_id = yt_channel_id_from_input(actor_link_norm0)

                    else:
                        channel_id = ""

                if not channel_id:
                    st.error("Could not resolve Channel ID for this submission. Please paste a /channel/UC... or /@handle URL.")
                    st.stop()

                ch_id_col = _find_col(latest, "Channel ID")
                latest_ids = set(latest[ch_id_col].astype(str).str.strip().tolist()) if ch_id_col else set()
                if channel_id in latest_ids:
                    st.warning("Someone added this channel just now — it already exists.")
                    st.dataframe(latest[latest[ch_id_col].astype(str).str.strip() == channel_id], use_container_width=True)
                    st.stop()

                # Fetch channel stats via API at submission time
                with st.spinner("Fetching channel details via YouTube API..."):
                    details = yt_fetch_channel_details(channel_id)

                actor_link_norm = normalize_youtube_url(actor_link)
                actor_link_final = yt_canonical_actor_link(actor_link_norm, channel_id)

                row = {
                    "actor_name": actor_name.strip(),
                    "actor_link": actor_link_final.strip(),
                    "affiliation": affiliation.strip(),
                    "evidence": evidence.strip(),
                    "Channel ID": channel_id,
                    # Keep these blank unless you later add UI for them:
                    "TAG": "",
                    "Comment": "",
                    # API-enriched fields:
                    "Channel Joined Date": details.get("Channel Joined Date", ""),
                    "Subscriber": details.get("Subscriber", ""),
                    "Channel Location": details.get("Channel Location", ""),
                    "Channel Total Videos": details.get("Channel Total Videos", ""),
                    "Channel Total Views": details.get("Channel Total Views", ""),
                    SUBMITTED_BY_COL: submitted_by.strip(),
                    DATE_SUBMITTED_COL: submitted_time_utc,
                }

                append_submission(sheet_name, platform, row)
                st.success("✅ Submitted and appended to the spreadsheet.")
                st.session_state.pending_add = False
                st.session_state.pending_key = ""
                st.session_state.pending_norm = ""
                st.cache_data.clear()
                st.dataframe(load_db(sheet_name, platform).tail(10), use_container_width=True)

with info_col:
    badge = "Facebook" if platform == "Facebook" else "YouTube"

    # Card wrapper (HTML)
    st.markdown(
        f"""
        <div class="sticky">
          <div class="card">
            <div style="display:flex;align-items:center;gap:8px;">
              <h4 style="margin:0;">How this works</h4>
              <span class="pill">{badge}</span>
            </div>
            <div class="muted" style="margin-top:0.5rem;">
              Check if an actor is already in the database. If not found, submit a new entry with evidence.
              Duplicate submissions are prevented.
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Content (Markdown — reliable rendering)
    st.markdown("### Steps")
    st.markdown(
        """
1. Select a platform  
2. Paste the actor URL and click **Check database**  
3. If not found, complete the form and submit  
"""
    )
