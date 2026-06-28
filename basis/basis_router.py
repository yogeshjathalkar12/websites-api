from fastapi import APIRouter

# Initialize the router for Basis
router = APIRouter()

# This endpoint will be available at: /api/basis/status
@router.get("/status")
def get_basis_status():
    return {"venture": "Basis", "status": "operational"}