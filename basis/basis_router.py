import os
import uuid
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime
from supabase import create_client, Client

# Assuming all your provided Pydantic models are saved in basis/schemas.py
from .schemas import (
    CitizenSignup, CitizenOut, WalletOut,
    ReportCreate, ReportOut,
    ShopCreate, ShopOut,
    VoucherCreate, VoucherOut, VoucherRedemption,
    DisposalActionCreate, DisposalActionOut,
    ProductCreate, ProductOut, ProductPurchase,
    RedemptionOut
)

# Initialize the router for Basis
router = APIRouter()
security = HTTPBearer()

# --- 1. CONNECT TO SUPABASE ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- SECURITY UTILS ---
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Validates the JWT Bearer token securely via Supabase."""
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    
    token = credentials.credentials
    try:
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return user_response.user.id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# --- 2. SYSTEM STATUS ---
@router.get("/status")
def get_basis_status():
    return {"venture": "Basis Marketplace", "status": "operational", "database_connected": supabase is not None}

# --- 3. CITIZEN & WALLET ROUTES ---
@router.post("/citizens/signup", response_model=CitizenOut, tags=["Citizens"])
def signup_citizen(citizen: CitizenSignup, user_id: str = Depends(get_current_user)):
    """Creates an opt-in identity for the credit system."""
    
    # Check if citizen already exists
    existing = supabase.table("basis_citizens").select("*").eq("user_id", user_id).execute()
    if existing.data:
        return existing.data[0]
        
    new_citizen_data = {
        "user_id": user_id,
        "email": citizen.email,
        "credits": 0
    }
    
    response = supabase.table("basis_citizens").insert(new_citizen_data).execute()
    if not response.data:
        raise HTTPException(status_code=500, detail="Failed to create citizen wallet")
        
    return response.data[0]

@router.get("/citizens/wallet", response_model=WalletOut, tags=["Citizens"])
def get_wallet(user_id: str = Depends(get_current_user)):
    """Fetches the current credit balance and stats for the authenticated citizen."""
    
    citizen_res = supabase.table("basis_citizens").select("credits").eq("user_id", user_id).execute()
    if not citizen_res.data:
        raise HTTPException(status_code=404, detail="Wallet not found")
        
    credits = citizen_res.data[0]["credits"]
    
    # Aggregate counts
    reports_res = supabase.table("basis_reports").select("id", count="exact").eq("citizen_id", user_id).execute()
    disposals_res = supabase.table("basis_disposals").select("id", count="exact").eq("citizen_id", user_id).execute()
    
    return WalletOut(
        citizen_id=user_id,
        credits=credits,
        total_earned=0, # Can be derived later via sum queries if needed
        total_spent=0,
        report_count=reports_res.count if reports_res.count else 0,
        disposal_count=disposals_res.count if disposals_res.count else 0
    )

# --- 4. EARNING CREDITS ---
@router.post("/reports", response_model=ReportOut, tags=["Earning"])
def file_credit_report(report: ReportCreate, user_id: str = Depends(get_current_user)):
    """Files a report to earn civic credits and updates the wallet."""
    
    report_data = report.model_dump()
    report_data["citizen_id"] = user_id
    
    rep_response = supabase.table("basis_reports").insert(report_data).execute()
    if not rep_response.data:
        raise HTTPException(status_code=500, detail="Failed to file report")
        
    # Update citizen credits
    citizen_res = supabase.table("basis_citizens").select("credits").eq("user_id", user_id).execute()
    current_credits = citizen_res.data[0]["credits"]
    
    new_credits = current_credits + report.credits_to_award
    supabase.table("basis_citizens").update({"credits": new_credits}).eq("user_id", user_id).execute()
    
    return rep_response.data[0]

@router.post("/shops/disposal", response_model=DisposalActionOut, tags=["Earning"])
def verify_disposal_action(action: DisposalActionCreate, user_id: str = Depends(get_current_user)):
    """Logs a verified waste disposal at a local shop to earn credits."""
    
    # 1. Verify Shop exists
    shop_res = supabase.table("basis_shops").select("name").eq("id", action.shop_id).execute()
    if not shop_res.data:
        raise HTTPException(status_code=404, detail="Shop not found")
        
    shop_name = shop_res.data[0]["name"]
    
    # 2. Insert Disposal Action
    action_data = action.model_dump()
    action_data["citizen_id"] = user_id
    action_data.pop("credits_to_award", None) # Ensure we don't accidentally override internal defaults
    
    # Force credits to award for security (could be fetched from shop settings in a real scenario)
    credits_awarded = action.credits_to_award 
    action_data["credits_awarded"] = credits_awarded
    
    disp_response = supabase.table("basis_disposals").insert(action_data).execute()
    
    # 3. Update citizen credits
    citizen_res = supabase.table("basis_citizens").select("credits").eq("user_id", user_id).execute()
    current_credits = citizen_res.data[0]["credits"]
    supabase.table("basis_citizens").update({"credits": current_credits + credits_awarded}).eq("user_id", user_id).execute()
    
    inserted_data = disp_response.data[0]
    inserted_data["shop_name"] = shop_name
    return inserted_data


# --- 5. SHOPS & VOUCHERS (The Local Economy) ---
@router.post("/shops", response_model=ShopOut, tags=["Economy"])
def register_shop(shop: ShopCreate, user_id: str = Depends(get_current_user)):
    """Registers a new local business."""
    
    shop_data = shop.model_dump()
    shop_data["owner_user_id"] = user_id
    
    response = supabase.table("basis_shops").insert(shop_data).execute()
    if not response.data:
        raise HTTPException(status_code=500, detail="Failed to register shop")
        
    return response.data[0]

@router.post("/vouchers", response_model=VoucherOut, tags=["Economy"])
def create_voucher(voucher: VoucherCreate, user_id: str = Depends(get_current_user)):
    """Allows a shop to issue a new discount voucher in exchange for credits."""
    
    # Verify ownership
    shop_res = supabase.table("basis_shops").select("id, name").eq("id", voucher.shop_id).eq("owner_user_id", user_id).execute()
    if not shop_res.data:
        raise HTTPException(status_code=403, detail="Not authorized to create vouchers for this shop")
        
    voucher_data = voucher.model_dump()
    response = supabase.table("basis_vouchers").insert(voucher_data).execute()
    
    inserted_data = response.data[0]
    inserted_data["shop_name"] = shop_res.data[0]["name"]
    return inserted_data


# --- 6. MARKETPLACE LISTINGS ---
@router.post("/products", response_model=ProductOut, tags=["Marketplace"])
def create_product(product: ProductCreate, user_id: str = Depends(get_current_user)):
    """Allows a verified shop owner to list a sustainable good on the marketplace."""
    
    shop_res = supabase.table("basis_shops").select("id, name").eq("owner_user_id", user_id).execute()
    if not shop_res.data:
        raise HTTPException(status_code=403, detail="You must register a shop before listing products.")
    
    shop_id = shop_res.data[0]["id"]
    shop_name = shop_res.data[0]["name"]

    product_data = product.model_dump()
    product_data["seller_shop_id"] = shop_id
    
    response = supabase.table("basis_products").insert(product_data).execute()
    if not response.data:
        raise HTTPException(status_code=500, detail="Failed to list product on the marketplace.")
        
    inserted_product = response.data[0]
    
    return ProductOut(
        id=inserted_product["id"],
        seller_shop_id=shop_id,
        shop_name=shop_name,
        title=inserted_product["title"],
        description=inserted_product["description"],
        category=inserted_product["category"],
        original_price=inserted_product["original_price"],
        credits_price=inserted_product["credits_price"],
        image_url=inserted_product.get("image_url"),
        stock=inserted_product.get("stock"),
        created_at=inserted_product["created_at"]
    )


# --- 7. REDEMPTIONS (Closing the Loop) ---
@router.post("/redemptions/voucher", response_model=RedemptionOut, tags=["Redemption"])
def redeem_voucher(redemption: VoucherRedemption, user_id: str = Depends(get_current_user)):
    """Safely executes an atomic transaction to deduct credits and claim a voucher."""
    
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection uninitialized")

    claim_code = f"BASIS-{uuid.uuid4().hex[:6].upper()}"

    try:
        rpc_response = supabase.rpc(
            "basis_redeem_voucher_tx",
            {
                "p_citizen_id": user_id,
                "p_voucher_id": redemption.voucher_id,
                "p_redemption_code": claim_code
            }
        ).execute()

        result = rpc_response.data
        if not result or not result.get("success"):
            error_msg = result.get("error", "Redemption transaction failed")
            if error_msg in ["Voucher is out of stock", "Insufficient credits", "Voucher has expired"]:
                raise HTTPException(status_code=400, detail=error_msg)
            raise HTTPException(status_code=500, detail=error_msg)

        return RedemptionOut(
            id=result["redemption_id"],
            citizen_id=user_id,
            type="voucher",
            reference_id=redemption.voucher_id,
            credits_spent=result["credits_spent"],
            redemption_code=claim_code,
            redeemed_at=datetime.utcnow()
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database transaction error: {str(e)}")


@router.post("/redemptions/product", response_model=RedemptionOut, tags=["Redemption"])
def purchase_product(purchase: ProductPurchase, user_id: str = Depends(get_current_user)):
    """Deducts credits to buy a physical product from the marketplace."""
    
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection uninitialized")

    claim_code = f"ITEM-{uuid.uuid4().hex[:6].upper()}"

    try:
        # Requires creating a basis_buy_product_tx RPC in Supabase (identical logic to voucher tx)
        rpc_response = supabase.rpc(
            "basis_buy_product_tx",
            {
                "p_citizen_id": user_id,
                "p_product_id": purchase.product_id,
                "p_redemption_code": claim_code
            }
        ).execute()

        result = rpc_response.data
        if not result or not result.get("success"):
            error_msg = result.get("error", "Purchase transaction failed")
            if error_msg in ["Product is out of stock", "Insufficient credits"]:
                raise HTTPException(status_code=400, detail=error_msg)
            raise HTTPException(status_code=500, detail=error_msg)

        return RedemptionOut(
            id=result["redemption_id"],
            citizen_id=user_id,
            type="product",
            reference_id=purchase.product_id,
            credits_spent=result["credits_spent"],
            redemption_code=claim_code,
            redeemed_at=datetime.utcnow()
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database transaction error: {str(e)}")
