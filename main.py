from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# --- 1. IMPORT YOUR VENTURES ---
# raptor_router.py is the original venture entry point (verify-email,
# tracker pixel, campaign-opens). Everything under raptor/utility/ is the
# set of 8 heavy-compute tools that were sitting in the repo unwired --
# each one is now imported and mounted below.
from raptor.raptor_router import router as raptor_router
from raptor.utility.chronos_router import router as chronos_router
from raptor.utility.kmeans_router import router as kmeans_router
from raptor.utility.montecarlo_router import router as montecarlo_router
from raptor.utility.resolver_router import router as resolver_router
from raptor.utility.spintax_router import router as spintax_router
from raptor.utility.threader_router import router as threader_router
from raptor.utility.vad_router import router as vad_router
from raptor.utility.video_router import router as video_router
from raptor.crm.automations_router import router as automations_router

# Initialize the main API hub
app = FastAPI(title="Websites Central API")

# --- 2. CORS POLICY (Crucial for GitHub Pages frontend) ---
# NOTE: allow_origins=["*"] together with allow_credentials=True is
# invalid per the CORS spec -- browsers will reject/ignore credentialed
# requests against a wildcard origin. Your auth currently uses Bearer
# tokens in headers (not cookies), so this wasn't actively breaking
# anything, but it's tightened here to your real domains so it stays
# correct if cookie-based auth is ever added, and so no arbitrary site
# can make credentialed requests against this API.
#
# Confirmed setup: site is hosted on GitHub Pages
# (yogeshjathalkar12.github.io) with shoonyaorigins.com mapped on top
# as a custom domain. Both URLs can serve the same content unless
# GitHub's "Enforce HTTPS"/custom-domain-only redirect fully blocks
# the .github.io URL, so both are allowed here to be safe.
ALLOWED_ORIGINS = [
    "https://shoonyaorigins.com",
    "https://www.shoonyaorigins.com",
    "https://yogeshjathalkar12.github.io",
    # Add your local dev origin here while testing, e.g.:
    # "http://127.0.0.1:5500",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 3. BASE SERVER ROUTE ---
@app.get("/")
def read_root():
    return {"status": "online", "message": "Central API Hub is running!"}

# --- 4. CONNECT YOUR VENTURE FOLDERS ---
# raptor_router keeps its existing top-level prefix (verify-email,
# generate-tracker, track, campaign-opens all still live at /api/raptor/...
# exactly as before -- nothing about the tracker/verifier URLs changes).
#
# The 8 utility tools each get their own sub-prefix under /api/raptor/,
# matching their file/folder location (raptor/utility/<tool>_router.py) so
# routes read as e.g. POST /api/raptor/kmeans/cluster,
# GET /api/raptor/chronos/scheduled, etc.
app.include_router(raptor_router, prefix="/api/raptor", tags=["Raptor"])
app.include_router(chronos_router, prefix="/api/raptor/chronos", tags=["Raptor - Chronos"])
app.include_router(kmeans_router, prefix="/api/raptor/kmeans", tags=["Raptor - K-Means"])
app.include_router(montecarlo_router, prefix="/api/raptor/montecarlo", tags=["Raptor - Monte Carlo"])
app.include_router(resolver_router, prefix="/api/raptor/resolver", tags=["Raptor - IP Resolver"])
app.include_router(spintax_router, prefix="/api/raptor/spintax", tags=["Raptor - Spintax"])
app.include_router(threader_router, prefix="/api/raptor/threader", tags=["Raptor - IMAP Threader"])
app.include_router(vad_router, prefix="/api/raptor/vad", tags=["Raptor - Call VAD"])
app.include_router(video_router, prefix="/api/raptor/video", tags=["Raptor - Video Compressor"])

# crm/automations_router.py is a cron-driven background worker, not a
# normal user-facing tool -- it's guarded by X-Automation-Secret (see
# AUTOMATION_CRON_SECRET in raptor/crm/automations_router.py), not a user
# JWT, so it deliberately sits outside the get_current_user/deduct_credit
# pattern the other routers use. Point your scheduler (cron job, Render
# Cron Job, GitHub Actions schedule, etc.) at POST /api/raptor/crm/run.
app.include_router(automations_router, prefix="/api/raptor/crm", tags=["Raptor - CRM Automations"])
