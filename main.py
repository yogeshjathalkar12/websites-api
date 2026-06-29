pafrom fastapi 
import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# --- 1. IMPORT YOUR VENTURES ---
# These imports look for the 'router.py' file inside the 'raptor', 'civitas', and 'basis' folders.
from raptor.router import router as raptor_router
from civitas.civitasrouter import router as civitas_router
from basis.router import router as basis_router

# Initialize the main API hub
app = FastAPI(title="Websites Central API")

# --- 2. CORS POLICY (Crucial for GitHub Pages frontend) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
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