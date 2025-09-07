import streamlit as st
import os, time, random, requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -------------------
# Page Config
# -------------------
st.set_page_config(page_title="Guest Posting Tool", page_icon="🚀", layout="wide")
st.title("🚀 Guest Posting Tool")
st.write("Welcome Faizan! 🎉 Manage guest posting with metrics, emails & outreach automation.")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; GuestBot/1.0)"}

# -------------------
# Helpers
# -------------------

# SEMrush
def get_semrush_domain_overview(domain, database="us"):
    key = os.getenv("SEMRUSH_API_KEY")
    if not key:
        return {"error": "Missing SEMRUSH_API_KEY"}
    url = "https://api.semrush.com/analytics/v1/domain/overview"
    params = {"key": key, "domain": domain, "database": database, "output": "json"}
    try:
        r = requests.get(url, params=params, headers=HEADERS, timeout=20)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# Ahrefs
def get_ahrefs_domain_metrics(domain):
    token = os.getenv("AHREFS_API_TOKEN")
    if not token:
        return {"error": "Missing AHREFS_API_TOKEN"}
    base = "https://apiv3.ahrefs.com"
    params = {"token": token, "target": domain, "from": "domain_rating"}
    try:
        r = requests.get(base, params=params, timeout=20)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# Moz
def get_moz_metrics(domain):
    moz_id = os.getenv("MOZ_ACCESS_ID")
    moz_key = os.getenv("MOZ_SECRET_KEY")
    if not moz_id or not moz_key:
        return {"error": "Missing MOZ creds"}
    try:
        url = "https://lsapi.seomoz.com/v2/url_metrics"
        r = requests.post(
            url,
            json={"targets": [f"https://{domain}"]},
            headers={"Authorization": f"AccessID {moz_id}", "Content-Type":"application/json"},
            timeout=20
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# Hunter
def verify_email_hunter(email):
    key = os.getenv("HUNTER_API_KEY")
    if not key:
        return {"error": "Missing HUNTER_API_KEY"}
    try:
        url = "https://api.hunter.io/v2/email-verifier"
        params = {"email": email, "api_key": key}
        r = requests.get(url, params=params, timeout=15)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# Snov
def snov_get_access_token():
    cid = os.getenv("SNOV_CLIENT_ID")
    secret = os.getenv("SNOV_CLIENT_SECRET")
    if not cid or not secret:
        return None
    try:
        r = requests.post("https://api.snov.io/v2/oauth/access_token",
                          json={"grant_type":"client_credentials","client_id":cid,"client_secret":secret},
                          timeout=15)
        return r.json().get("access_token")
    except:
        return None

def verify_emails_snov_bulk(emails: list):
    token = snov_get_access_token()
    if not token:
        return {"error": "Missing SNOV token"}
    try:
        r = requests.post("https://api.snov.io/v2/email-verifier/bulk",
                          json={"emails": emails},
                          headers={"Authorization": f"Bearer {token}"},
                          timeout=20)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# Proxy + Rate limiting
PROXY_LIST = os.getenv("PROXY_LIST", "")
SCRAPE_DELAY = float(os.getenv("SCRAPE_DELAY", "0.5"))

def build_session(use_proxy=False):
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429,500,502,503,504])
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    if use_proxy and PROXY_LIST:
        proxies = [p.strip() for p in PROXY_LIST.split(",") if p.strip()]
        if proxies:
            sel = random.choice(proxies)
            s.proxies.update({"http": sel, "https": sel})
    return s

def safe_get(url, session=None, timeout=15):
    s = session or build_session()
    try:
        r = s.get(url, headers=HEADERS, timeout=timeout)
        time.sleep(SCRAPE_DELAY)
        return r
    except:
        return None

# Outreach Templates
OUTREACH_SEQUENCES = {
    "D1 Pitch": "Hi {name}, I’d love to contribute a guest post idea: {topic}. Would you be open to it?",
    "D4 Bump": "Hi {name}, just checking in on my guest post pitch about {topic}. Happy to adjust.",
    "D9 Final": "Hi {name}, one last follow-up on my guest post idea for {topic}. If now’s not a good time, no worries!"
}

# -------------------
# UI
# -------------------

st.sidebar.header("🔧 Actions")
use_proxy = st.sidebar.checkbox("Use Proxy", value=False)

# Enrichment
if st.sidebar.button("Enrich Domain (DA/DR/Traffic)"):
    domain = st.text_input("Enter domain to enrich:")
    if domain:
        sem = get_semrush_domain_overview(domain)
        ah = get_ahrefs_domain_metrics(domain)
        moz = get_moz_metrics(domain)
        st.subheader("📊 Domain Metrics")
        st.json({"SEMrush": sem, "Ahrefs": ah, "Moz": moz})

# Email Verify
if st.sidebar.button("Verify Emails"):
    email = st.text_input("Enter email to verify:")
    if email:
        res1 = verify_email_hunter(email)
        res2 = verify_emails_snov_bulk([email])
        st.subheader("📧 Email Verification Results")
        st.json({"Hunter": res1, "Snov": res2})

# Outreach
if st.sidebar.button("Generate Outreach"):
    template = st.selectbox("Choose Template", list(OUTREACH_SEQUENCES.keys()))
    name = st.text_input("Recipient name", "Editor")
    topic = st.text_input("Topic", "SEO strategies for SaaS")
    msg = OUTREACH_SEQUENCES[template].format(name=name, topic=topic)
    st.subheader("✉️ Outreach Email")
    st.code(msg)
