# OrderFlow — Main Application
#
# CORS is configured for the React frontend and GET /products is protected
# by the JWT auth dependency from auth.py.

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from auth import router as auth_router, get_current_user, User

app = FastAPI(title="OrderFlow API — L2")


# CORS middleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Auth router — exposes POST /auth/login at /docs

app.include_router(auth_router)


# Sample data (do not modify)

PRODUCTS = [
    {"product_id": 1, "name": "Laptop",   "price": 999.99},
    {"product_id": 2, "name": "Keyboard", "price":  49.99},
    {"product_id": 3, "name": "Monitor",  "price": 299.99},
]


class OrderRequest(BaseModel):
    product_id: int
    quantity: int


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/products")
def get_products(current_user: User = Depends(get_current_user)):
    # Protected — requires a valid JWT
    return PRODUCTS


@app.post("/orders", status_code=201)
def create_order(order: OrderRequest):
    # Public endpoint — no auth required
    return {
        "message": f"Order placed for product {order.product_id}",
        "quantity": order.quantity,
    }
