"""The one public door for data other services push to Raptor: payments, webhooks and Telegram messages.

POST /api/raptor/hooks/{token}. The token is a long random address that belongs to one connection. There is no login on this route
(Razorpay, Stripe and Telegram cannot log in), so everything is checked in router.receive_push: the token must belong to an inbound
connection, the message must carry a valid signature, the size and the rate are limited, and nothing about the connection is
revealed in an error."""
from fastapi import APIRouter, Request

from . import router as connections_router

router = APIRouter()


@router.post("/{token}")
async def receive(token: str, request: Request):
    body = await request.body()
    return connections_router.receive_push(token, body, dict(request.headers))
