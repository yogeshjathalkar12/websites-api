from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# --- 1. IMPORT YOUR VENTURES ---
# These imports look for the 'router.py' file inside the 'raptor', 'civitas', and 'basis' folders.
from raptor.router import router as raptor_router
from civitas.civitasrouter import router as civitas_router
from basis.router import router as basis_router

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
# This automatically routes requests like /api/raptor/... to the raptor folder
app.include_router(raptor_router, prefix="/api/raptor", tags=["Raptor"])
app.include_router(civitas_router, prefix="/api/civitas", tags=["Civitas"])
app.include_router(basis_router, prefix="/api/basis", tags=["Basis"])
