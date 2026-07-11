from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Request, Response
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os
import logging
import asyncio
import bcrypt
import jwt
import secrets
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import uuid
from datetime import datetime, timezone, timedelta
from emergentintegrations.payments.stripe.checkout import (
    StripeCheckout, CheckoutSessionResponse, CheckoutStatusResponse, CheckoutSessionRequest
)
import stripe
try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TwilioClient = None
    TWILIO_AVAILABLE = False

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=5000)
db = client[os.environ.get('DB_NAME', 'test_database')]

app = FastAPI()
api_router = APIRouter(prefix="/api")

JWT_ALGORITHM = "HS256"

# ── Subscription Plans ──────────────────────────────────

SUBSCRIPTION_PLANS = {
    "free": {"name": "Free", "price": 0.0, "max_contacts": 1, "features": ["Basic smoke detection", "1 emergency contact", "Local alarm only"], "duration_days": 0, "includes_satellite": False, "satellite_count": 0},
    "pro": {"name": "Pro", "price": 3.99, "max_contacts": 5, "features": ["5 contacts + EMT auto-dial", "GPS sharing", "Call history", "Priority alerts"], "duration_days": 30, "includes_satellite": False, "satellite_count": 0},
    "satellite": {"name": "Satellite", "price": 2.99, "max_contacts": 1, "features": ["1 Satellite device", "Custom voice alert message", "Auto-call owner when alarm sounds", "SMS with GPS location to owner"], "duration_days": 30, "includes_satellite": True, "satellite_count": 1},
    "pro_satellite": {"name": "Pro + Satellite", "price": 6.98, "max_contacts": 5, "features": ["Everything in Pro", "1 Satellite device included", "Custom voice alert message", "Auto-call + SMS on alarm", "Best value bundle"], "duration_days": 30, "includes_satellite": True, "satellite_count": 1},
    "extra_satellite": {"name": "Extra Satellite", "price": 1.99, "max_contacts": 0, "features": ["Add 1 more Satellite device", "Monitor an extra room or area", "Same custom voice + auto-call", "Stack multiple for whole-home coverage"], "duration_days": 30, "includes_satellite": True, "satellite_count": 1, "is_addon": True},
    "family": {"name": "Family", "price": 7.99, "max_contacts": 5, "features": ["Multi-device sync (5 phones)", "SMS alerts to family", "Cloud alert logs", "All Pro features", "1 Satellite device included"], "duration_days": 30, "includes_satellite": True, "satellite_count": 1},
    "pro_yearly": {"name": "Pro Yearly", "price": 33.50, "max_contacts": 5, "features": ["Everything in Pro", "Save 30% vs monthly", "Billed annually"], "duration_days": 365, "includes_satellite": False, "satellite_count": 0, "billing": "yearly"},
    "pro_satellite_yearly": {"name": "Pro + Satellite Yearly", "price": 58.63, "max_contacts": 5, "features": ["Everything in Pro + Satellite", "Save 30% vs monthly", "Billed annually"], "duration_days": 365, "includes_satellite": True, "satellite_count": 1, "billing": "yearly"},
    "family_yearly": {"name": "Family Yearly", "price": 67.11, "max_contacts": 5, "features": ["Everything in Family", "Save 30% vs monthly", "Billed annually"], "duration_days": 365, "includes_satellite": True, "satellite_count": 1, "billing": "yearly"},
}

# ── Password Helpers ────────────────────────────────────

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

# ── JWT Helpers ─────────────────────────────────────────

def get_jwt_secret() -> str:
    return os.environ.get("JWT_SECRET", "default-change-me-in-production")

def create_access_token(user_id: str, email: str) -> str:
    payload = {"sub": user_id, "email": email, "exp": datetime.now(timezone.utc) + timedelta(minutes=60), "type": "access"}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    payload = {"sub": user_id, "exp": datetime.now(timezone.utc) + timedelta(days=7), "type": "refresh"}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")

async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_optional_user(request: Request) -> Optional[dict]:
    try:
        return await get_current_user(request)
    except HTTPException:
        return None

# ── Auth Models ─────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = ""

class LoginRequest(BaseModel):
    email: str
    password: str

# ── Auth Endpoints ──────────────────────────────────────

@api_router.post("/auth/register")
async def register(data: RegisterRequest, response: Response):
    email = data.email.strip().lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_doc = {
        "email": email,
        "password_hash": hash_password(data.password),
        "name": data.name or email.split("@")[0],
        "role": "user",
        "subscription": "free",
        "subscription_expires": None,
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)
    
    access = create_access_token(user_id, email)
    refresh = create_refresh_token(user_id)
    set_auth_cookies(response, access, refresh)
    
    return {
        "id": user_id, "email": email, "name": user_doc["name"],
        "role": "user", "subscription": "free",
        "access_token": access, "refresh_token": refresh
    }

@api_router.post("/auth/login")
async def login(data: LoginRequest, request: Request, response: Response):
    email = data.email.strip().lower()
    ip = request.client.host if request.client else "unknown"
    identifier = f"{ip}:{email}"
    
    # Brute force check
    attempts = await db.login_attempts.find_one({"identifier": identifier})
    if attempts and attempts.get("count", 0) >= 5:
        last = attempts.get("last_attempt")
        if last and isinstance(last, datetime):
            last_aware = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - last_aware).total_seconds() < 900:
                raise HTTPException(status_code=429, detail="Too many attempts. Try again in 15 minutes.")
    
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(data.password, user["password_hash"]):
        await db.login_attempts.update_one(
            {"identifier": identifier},
            {"$inc": {"count": 1}, "$set": {"last_attempt": datetime.now(timezone.utc)}},
            upsert=True
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Clear attempts on success
    await db.login_attempts.delete_one({"identifier": identifier})
    
    user_id = str(user["_id"])
    access = create_access_token(user_id, email)
    refresh = create_refresh_token(user_id)
    set_auth_cookies(response, access, refresh)
    
    # Check subscription status
    sub = user.get("subscription", "free")
    sub_expires = user.get("subscription_expires")
    if sub_expires and isinstance(sub_expires, datetime) and sub != "free":
        exp = sub_expires if sub_expires.tzinfo else sub_expires.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            await db.users.update_one({"_id": user["_id"]}, {"$set": {"subscription": "free", "subscription_expires": None}})
            sub = "free"
    
    return {
        "id": user_id, "email": email, "name": user.get("name", ""),
        "role": user.get("role", "user"), "subscription": sub,
        "access_token": access, "refresh_token": refresh
    }

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"status": "logged out"}

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    sub = user.get("subscription", "free")
    sub_expires = user.get("subscription_expires")
    if sub_expires and isinstance(sub_expires, datetime) and sub != "free":
        exp = sub_expires if sub_expires.tzinfo else sub_expires.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$set": {"subscription": "free", "subscription_expires": None}})
            sub = "free"
            user["subscription"] = "free"
    return {
        "id": user["_id"], "email": user["email"], "name": user.get("name", ""),
        "role": user.get("role", "user"), "subscription": sub,
        "subscription_expires": sub_expires.isoformat() if isinstance(sub_expires, datetime) else None,
    }

@api_router.post("/auth/refresh")
async def refresh_token(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user_id = str(user["_id"])
        access = create_access_token(user_id, user["email"])
        response.set_cookie(key="access_token", value=access, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
        return {"access_token": access}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

# ── Subscription & Stripe Endpoints ─────────────────────

# Initialize Stripe
stripe.api_key = os.environ.get("STRIPE_API_KEY")

# Store Stripe Price IDs after creation
STRIPE_PRICES = {}

async def ensure_stripe_products():
    """Create Stripe products and recurring prices on startup."""
    global STRIPE_PRICES
    try:
        for plan_id, plan in SUBSCRIPTION_PLANS.items():
            if plan_id == "free" or plan["price"] == 0:
                continue
            
            # Check if we already stored the price ID
            existing = await db.stripe_config.find_one({"plan_id": plan_id}, {"_id": 0})
            if existing and existing.get("price_id"):
                STRIPE_PRICES[plan_id] = existing["price_id"]
                continue
            
            # Create product
            product = stripe.Product.create(
                name=f"THE FIRE APP - {plan['name']} Plan",
                description=", ".join(plan["features"]),
            )
            
            # Create recurring price (monthly or yearly)
            billing = plan.get("billing", "monthly")
            interval = "year" if billing == "yearly" else "month"
            price = stripe.Price.create(
                product=product.id,
                unit_amount=int(plan["price"] * 100),
                currency="usd",
                recurring={"interval": interval},
            )
            
            STRIPE_PRICES[plan_id] = price.id
            await db.stripe_config.update_one(
                {"plan_id": plan_id},
                {"$set": {"plan_id": plan_id, "product_id": product.id, "price_id": price.id}},
                upsert=True
            )
            logger.info(f"Created Stripe product for {plan_id}: {price.id}")
    except Exception as e:
        logger.error(f"Stripe product setup error (non-fatal): {e}")

@api_router.get("/subscription/plans")
async def get_plans():
    return SUBSCRIPTION_PLANS

@api_router.post("/subscription/checkout")
async def create_checkout(request: Request):
    user = await get_current_user(request)
    body = await request.json()
    plan_id = body.get("plan_id", "pro")
    origin_url = body.get("origin_url", "")
    
    if plan_id not in SUBSCRIPTION_PLANS or plan_id == "free":
        raise HTTPException(status_code=400, detail="Invalid plan")
    
    price_id = STRIPE_PRICES.get(plan_id)
    if not price_id:
        raise HTTPException(status_code=400, detail="Plan not available yet. Please try again.")
    
    try:
        # Get or create Stripe customer
        stripe_customer_id = None
        user_doc = await db.users.find_one({"_id": ObjectId(user["_id"])})
        if user_doc and user_doc.get("stripe_customer_id"):
            stripe_customer_id = user_doc["stripe_customer_id"]
        else:
            customer = stripe.Customer.create(
                email=user["email"],
                name=user.get("name", ""),
                metadata={"user_id": user["_id"]},
            )
            stripe_customer_id = customer.id
            await db.users.update_one(
                {"_id": ObjectId(user["_id"])},
                {"$set": {"stripe_customer_id": stripe_customer_id}}
            )
        
        success_url = f"{origin_url}/subscription?session_id={{CHECKOUT_SESSION_ID}}"
        cancel_url = f"{origin_url}/subscription"
        
        # Create subscription checkout session
        session = stripe.checkout.Session.create(
            customer=stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={"user_id": user["_id"], "plan_id": plan_id},
        )
        
        # Record transaction
        await db.payment_transactions.insert_one({
            "session_id": session.id,
            "user_id": user["_id"],
            "user_email": user["email"],
            "plan_id": plan_id,
            "amount": SUBSCRIPTION_PLANS[plan_id]["price"],
            "currency": "usd",
            "payment_status": "pending",
            "subscription_mode": "recurring",
            "created_at": datetime.now(timezone.utc),
        })
        
        return {"url": session.url, "session_id": session.id}
    except Exception as e:
        logger.error(f"Checkout error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@api_router.get("/subscription/status/{session_id}")
async def check_subscription_status(session_id: str, request: Request):
    user = await get_current_user(request)
    
    txn = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    if txn.get("payment_status") == "paid":
        return {"status": "complete", "payment_status": "paid", "plan_id": txn.get("plan_id")}
    
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        
        if session.payment_status == "paid":
            existing = await db.payment_transactions.find_one({"session_id": session_id, "payment_status": "paid"})
            if not existing:
                plan_id = txn.get("plan_id", "pro")
                
                await db.payment_transactions.update_one(
                    {"session_id": session_id},
                    {"$set": {
                        "payment_status": "paid",
                        "stripe_subscription_id": session.subscription,
                        "paid_at": datetime.now(timezone.utc)
                    }}
                )
                
                await db.users.update_one(
                    {"_id": ObjectId(user["_id"])},
                    {"$set": {
                        "subscription": plan_id,
                        "stripe_subscription_id": session.subscription,
                        "subscription_status": "active",
                    }}
                )
        
        return {"status": session.status, "payment_status": session.payment_status, "plan_id": txn.get("plan_id")}
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return {"status": "pending", "payment_status": "pending", "plan_id": txn.get("plan_id")}

@api_router.get("/subscription/manage")
async def get_customer_portal(request: Request):
    """Get Stripe Customer Portal URL for managing subscription."""
    user = await get_current_user(request)
    user_doc = await db.users.find_one({"_id": ObjectId(user["_id"])})
    
    if not user_doc or not user_doc.get("stripe_customer_id"):
        raise HTTPException(status_code=400, detail="No active subscription found")
    
    try:
        origin_url = request.headers.get("origin", "")
        session = stripe.billing_portal.Session.create(
            customer=user_doc["stripe_customer_id"],
            return_url=f"{origin_url}/subscription",
        )
        return {"url": session.url}
    except Exception as e:
        logger.error(f"Portal error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events for subscription management."""
    try:
        body = await request.body()
        event = stripe.Event.construct_from(
            stripe.util.convert_to_stripe_object(
                stripe.util.json.loads(body), stripe.api_key
            ), stripe.api_key
        )
        
        event_type = event.type
        data = event.data.object
        
        # Checkout completed — activate subscription
        if event_type == "checkout.session.completed":
            if data.mode == "subscription" and data.payment_status == "paid":
                user_id = data.metadata.get("user_id")
                plan_id = data.metadata.get("plan_id", "pro")
                if user_id:
                    await db.users.update_one(
                        {"_id": ObjectId(user_id)},
                        {"$set": {
                            "subscription": plan_id,
                            "stripe_subscription_id": data.subscription,
                            "subscription_status": "active",
                        }}
                    )
                    await db.payment_transactions.update_one(
                        {"session_id": data.id},
                        {"$set": {"payment_status": "paid", "paid_at": datetime.now(timezone.utc)}}
                    )
        
        # Invoice paid — recurring payment succeeded
        elif event_type == "invoice.paid":
            sub_id = data.subscription
            if sub_id:
                await db.users.update_one(
                    {"stripe_subscription_id": sub_id},
                    {"$set": {"subscription_status": "active"}}
                )
        
        # Payment failed — Stripe will retry automatically
        elif event_type == "invoice.payment_failed":
            sub_id = data.subscription
            if sub_id:
                await db.users.update_one(
                    {"stripe_subscription_id": sub_id},
                    {"$set": {"subscription_status": "past_due"}}
                )
        
        # Subscription cancelled
        elif event_type == "customer.subscription.deleted":
            sub_id = data.id
            await db.users.update_one(
                {"stripe_subscription_id": sub_id},
                {"$set": {"subscription": "free", "subscription_status": "cancelled", "stripe_subscription_id": None}}
            )
        
        # Subscription updated (upgrade/downgrade)
        elif event_type == "customer.subscription.updated":
            sub_id = data.id
            status = data.status
            if status == "active":
                await db.users.update_one(
                    {"stripe_subscription_id": sub_id},
                    {"$set": {"subscription_status": "active"}}
                )
            elif status in ("past_due", "unpaid"):
                await db.users.update_one(
                    {"stripe_subscription_id": sub_id},
                    {"$set": {"subscription_status": status}}
                )
            elif status == "canceled":
                await db.users.update_one(
                    {"stripe_subscription_id": sub_id},
                    {"$set": {"subscription": "free", "subscription_status": "cancelled"}}
                )
        
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"status": "error"}

# ── Contact Models & Endpoints ──────────────────────────

class Contact(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    phone: str = ""
    order: int = 1
    is_emt: bool = False

class ContactsPayload(BaseModel):
    contacts: List[Contact]

# ── Satellite Device Endpoints ──────────────────────────

class SatelliteRegister(BaseModel):
    name: str = "Home Smoke Detector"
    home_address: str = ""
    home_gps_lat: float = 0
    home_gps_lng: float = 0
    owner_phone: str = ""
    custom_message: str = ""

class SatelliteAlarmTrigger(BaseModel):
    device_id: str
    sound_level: float = 0

@api_router.post("/satellite/register")
async def register_satellite(data: SatelliteRegister, request: Request):
    """Register a satellite device and link it to the owner's account."""
    user = await get_current_user(request)
    
    device_id = str(uuid.uuid4())[:8].upper()
    device_code = f"SAT-{device_id}"
    
    custom_msg = data.custom_message or f"This is an emergency alert from THE FIRE APP. The smoke alarm at {data.home_address or 'your home'} has detected smoke. Please investigate immediately."
    
    device = {
        "device_id": device_code,
        "user_id": user["_id"],
        "owner_email": user["email"],
        "owner_phone": data.owner_phone,
        "name": data.name,
        "home_address": data.home_address,
        "home_gps_lat": data.home_gps_lat,
        "home_gps_lng": data.home_gps_lng,
        "custom_message": custom_msg,
        "status": "online",
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "alarm_count": 0,
    }
    
    await db.satellites.insert_one(device)
    device.pop("_id", None)
    return device

@api_router.get("/satellite/devices")
async def get_satellite_devices(request: Request):
    """Get all satellite devices for the current user."""
    user = await get_current_user(request)
    devices = await db.satellites.find({"user_id": user["_id"]}, {"_id": 0}).to_list(20)
    return {"devices": devices, "total": len(devices)}

@api_router.put("/satellite/{device_id}")
async def update_satellite(device_id: str, request: Request):
    """Update satellite device settings."""
    user = await get_current_user(request)
    body = await request.json()
    
    device = await db.satellites.find_one({"device_id": device_id, "user_id": user["_id"]})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    update_fields = {}
    for field in ["name", "home_address", "home_gps_lat", "home_gps_lng", "owner_phone", "custom_message"]:
        if field in body:
            update_fields[field] = body[field]
    
    if update_fields:
        await db.satellites.update_one({"device_id": device_id}, {"$set": update_fields})
    
    updated = await db.satellites.find_one({"device_id": device_id}, {"_id": 0})
    return updated

@api_router.delete("/satellite/{device_id}")
async def delete_satellite(device_id: str, request: Request):
    """Delete a satellite device."""
    user = await get_current_user(request)
    result = await db.satellites.delete_one({"device_id": device_id, "user_id": user["_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"status": "deleted", "device_id": device_id}

@api_router.post("/satellite/heartbeat/{device_id}")
async def satellite_heartbeat(device_id: str):
    """Satellite device sends heartbeat to confirm it's online."""
    await db.satellites.update_one(
        {"device_id": device_id},
        {"$set": {"status": "online", "last_heartbeat": datetime.now(timezone.utc).isoformat()}}
    )
    return {"status": "ok"}

@api_router.post("/satellite/alarm")
async def satellite_alarm_triggered(data: SatelliteAlarmTrigger):
    """Called when satellite device detects smoke alarm sound. Triggers calls to owner."""
    device = await db.satellites.find_one({"device_id": data.device_id}, {"_id": 0})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    owner_phone = device.get("owner_phone", "")
    custom_message = device.get("custom_message", "Smoke alarm detected at your home!")
    home_address = device.get("home_address", "Unknown location")
    home_lat = device.get("home_gps_lat", 0)
    home_lng = device.get("home_gps_lng", 0)
    device_name = device.get("name", "Satellite Device")
    
    # Update device status
    await db.satellites.update_one(
        {"device_id": data.device_id},
        {"$set": {"status": "alarm", "last_alarm": datetime.now(timezone.utc).isoformat()},
         "$inc": {"alarm_count": 1}}
    )
    
    # Log the alarm event
    alarm_event = {
        "id": str(uuid.uuid4()),
        "device_id": data.device_id,
        "device_name": device_name,
        "user_id": device.get("user_id"),
        "type": "satellite_alarm",
        "home_address": home_address,
        "home_gps_lat": home_lat,
        "home_gps_lng": home_lng,
        "sound_level": data.sound_level,
        "status": "triggered",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "call_status": "pending",
    }
    await db.satellite_alarms.insert_one(alarm_event)
    alarm_event.pop("_id", None)
    
    # Make Twilio call to owner with custom message
    if owner_phone:
        loop = asyncio.get_event_loop()
        
        # Build TwiML with owner's custom message
        twiml_message = (
            f'<Response>'
            f'<Say voice="alice" loop="3">{custom_message} '
            f'Location: {home_address}. '
            f'Please investigate immediately.</Say>'
            f'<Pause length="2"/>'
            f'<Say voice="alice">GPS coordinates: {home_lat}, {home_lng}. '
            f'Open your Fire App for more details.</Say>'
            f'</Response>'
        )
        
        try:
            twilio_client = get_twilio_client()
            from_number = os.environ.get("TWILIO_PHONE_NUMBER")
            if twilio_client and from_number:
                call = twilio_client.calls.create(
                    to=owner_phone,
                    from_=from_number,
                    twiml=twiml_message,
                    timeout=30,
                )
                await db.satellite_alarms.update_one(
                    {"id": alarm_event["id"]},
                    {"$set": {"call_status": "initiated", "call_sid": call.sid}}
                )
                
                # Also send SMS
                maps_link = f"https://maps.google.com/?q={home_lat},{home_lng}"
                sms_body = (
                    f"🚨 SATELLITE ALARM - {device_name}\n\n"
                    f"{custom_message}\n\n"
                    f"📍 Location: {home_address}\n"
                    f"🗺 Map: {maps_link}\n\n"
                    f"Open THE FIRE APP for details."
                )
                twilio_client.messages.create(
                    to=owner_phone,
                    from_=from_number,
                    body=sms_body,
                )
        except Exception as e:
            logger.error(f"Satellite alarm call failed: {e}")
            await db.satellite_alarms.update_one(
                {"id": alarm_event["id"]},
                {"$set": {"call_status": "failed", "error": str(e)}}
            )
    
    # Also call emergency contacts if user has them
    user_id = device.get("user_id")
    if user_id:
        contacts = await db.contacts.find({"user_id": user_id, "is_emt": False}, {"_id": 0}).sort("order", 1).limit(5).to_list(5)
        for contact in contacts:
            contact_phone = contact.get("phone")
            if contact_phone:
                try:
                    twilio_client = get_twilio_client()
                    from_number = os.environ.get("TWILIO_PHONE_NUMBER")
                    if twilio_client and from_number:
                        twilio_client.messages.create(
                            to=contact_phone,
                            from_=from_number,
                            body=f"🚨 FIRE ALERT from THE FIRE APP\n\n{custom_message}\n\n📍 {home_address}\n🗺 https://maps.google.com/?q={home_lat},{home_lng}",
                        )
                except Exception as e:
                    logger.error(f"Contact SMS failed: {e}")
    
    return alarm_event

@api_router.post("/satellite/alarm/{device_id}/dismiss")
async def dismiss_satellite_alarm(device_id: str, request: Request):
    """Owner dismisses the satellite alarm."""
    user = await get_current_user(request)
    
    await db.satellites.update_one(
        {"device_id": device_id, "user_id": user["_id"]},
        {"$set": {"status": "online"}}
    )
    
    await db.satellite_alarms.update_many(
        {"device_id": device_id, "status": "triggered"},
        {"$set": {"status": "dismissed", "dismissed_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    return {"status": "dismissed"}

@api_router.get("/satellite/alarms")
async def get_satellite_alarms(request: Request):
    """Get alarm history for satellite devices."""
    user = await get_current_user(request)
    alarms = await db.satellite_alarms.find(
        {"user_id": user["_id"]}, {"_id": 0}
    ).sort("created_at", -1).limit(50).to_list(50)
    return {"alarms": alarms, "total": len(alarms)}

# ── Heat Detection Settings & Endpoints ─────────────────

class HeatSettings(BaseModel):
    enabled: bool = True
    threshold_f: float = 100.0  # Fahrenheit
    heat_sensitivity: int = 50  # 0-100 camera sensitivity
    warning_enabled: bool = True
    full_alarm_on_rising: bool = True

@api_router.get("/heat/settings")
async def get_heat_settings(request: Request):
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    settings = await db.heat_settings.find_one({"user_id": user_id}, {"_id": 0})
    if not settings:
        return HeatSettings().dict()
    settings.pop("user_id", None)
    return settings

@api_router.post("/heat/settings")
async def save_heat_settings(data: HeatSettings, request: Request):
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    doc = data.dict()
    doc["user_id"] = user_id
    await db.heat_settings.update_one(
        {"user_id": user_id}, {"$set": doc}, upsert=True
    )
    return {"status": "saved"}

@api_router.post("/heat/alert")
async def create_heat_alert(request: Request):
    """Create a heat alert — warning or full alarm based on severity."""
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    body = await request.json()
    
    heat_score = body.get("heat_score", 0)
    heat_level = body.get("heat_level", "warning")  # "warning" or "critical"
    gps_lat = body.get("gps_lat", 0)
    gps_lng = body.get("gps_lng", 0)
    gps_address = body.get("gps_address", "Unknown")
    source = body.get("source", "camera")  # "camera", "barometer", "satellite"
    device_id = body.get("device_id", None)
    
    alert = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "type": "heat",
        "heat_score": heat_score,
        "heat_level": heat_level,
        "source": source,
        "device_id": device_id,
        "gps_lat": gps_lat,
        "gps_lng": gps_lng,
        "gps_address": gps_address,
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dismissed_at": None,
    }
    await db.heat_alerts.insert_one(alert)
    alert.pop("_id", None)
    
    # If critical — trigger full alarm flow (call contacts)
    if heat_level == "critical":
        # Create a regular alert for the calling system
        smoke_alert = {
            "id": alert["id"],
            "user_id": user_id,
            "status": "alarm",
            "gps_lat": gps_lat,
            "gps_lng": gps_lng,
            "gps_address": gps_address,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "dismissed_at": None,
            "dismissed_by": None,
            "current_call_index": -1,
            "call_log": [],
            "countdown_seconds": 180,
            "alert_type": "heat",
        }
        await db.alerts.insert_one(smoke_alert)
    
    return alert

@api_router.post("/heat/alert/{alert_id}/dismiss")
async def dismiss_heat_alert(alert_id: str, request: Request):
    await db.heat_alerts.update_one(
        {"id": alert_id},
        {"$set": {"status": "dismissed", "dismissed_at": datetime.now(timezone.utc).isoformat()}}
    )
    await db.alerts.update_one(
        {"id": alert_id},
        {"$set": {"status": "dismissed", "dismissed_at": datetime.now(timezone.utc).isoformat(), "dismissed_by": "user_button"}}
    )
    return {"status": "dismissed"}

@api_router.get("/heat/alerts")
async def get_heat_alerts(request: Request):
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    alerts = await db.heat_alerts.find(
        {"user_id": user_id}, {"_id": 0}
    ).sort("created_at", -1).limit(50).to_list(50)
    return {"alerts": alerts, "total": len(alerts)}

@api_router.get("/contacts", response_model=List[Contact])
async def get_contacts(request: Request):
    user = await get_optional_user(request)
    query = {"user_id": user["_id"]} if user else {}
    contacts = await db.contacts.find(query, {"_id": 0}).sort("order", 1).limit(10).to_list(10)
    return [Contact(**c) for c in contacts]

@api_router.post("/contacts")
async def save_contacts(payload: ContactsPayload, request: Request):
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    
    # Check subscription limits
    sub = user.get("subscription", "free") if user else "free"
    plan = SUBSCRIPTION_PLANS.get(sub, SUBSCRIPTION_PLANS["free"])
    max_contacts = plan["max_contacts"]
    
    regular_contacts = [c for c in payload.contacts if not c.is_emt]
    if len(regular_contacts) > max_contacts:
        # Allow saving but only the allowed number will be active
        pass
    
    await db.contacts.delete_many({"user_id": user_id})
    for contact in payload.contacts:
        doc = contact.dict()
        doc["user_id"] = user_id
        await db.contacts.insert_one(doc)
    return {"status": "saved", "count": len(payload.contacts)}

@api_router.get("/contacts/default")
async def get_default_contacts(request: Request):
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    
    existing = await db.contacts.find({"user_id": user_id}, {"_id": 0}).to_list(10)
    if existing:
        return [Contact(**c) for c in existing]
    
    defaults = []
    for i in range(1, 6):
        defaults.append(Contact(id=str(uuid.uuid4()), name=f"Emergency Contact {i}", phone="", order=i, is_emt=False))
    defaults.append(Contact(id=str(uuid.uuid4()), name="911 / EMT", phone="911", order=0, is_emt=True))
    return defaults

# ── Alert Models & Endpoints ────────────────────────────

class AlertCreate(BaseModel):
    gps_lat: Optional[float] = None
    gps_lng: Optional[float] = None
    gps_address: Optional[str] = None

class AlertResponse(BaseModel):
    id: str
    status: str
    gps_lat: Optional[float] = None
    gps_lng: Optional[float] = None
    gps_address: Optional[str] = None
    created_at: str
    dismissed_at: Optional[str] = None
    dismissed_by: Optional[str] = None
    current_call_index: int = -1
    call_log: List[dict] = []
    countdown_seconds: int = 180

class CallStatusResponse(BaseModel):
    alert_id: str
    status: str
    current_call_index: int
    current_contact_name: str = ""
    current_contact_phone: str = ""
    call_log: List[dict] = []
    someone_answered: bool = False

active_call_tasks: Dict[str, asyncio.Task] = {}

def get_twilio_client():
    """Get Twilio client from environment variables."""
    if not TWILIO_AVAILABLE:
        return None
    account_sid = os.environ.get("TWILIO_ACCOUNT_SID")
    auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
    if account_sid and auth_token:
        return TwilioClient(account_sid, auth_token)
    return None

def make_twilio_call(to_number: str, gps_address: str) -> dict:
    """Make a real Twilio voice call with 'Smoke Detected' announcement and GPS location."""
    twilio_client = get_twilio_client()
    from_number = os.environ.get("TWILIO_PHONE_NUMBER")
    
    if not twilio_client or not from_number:
        return {"status": "failed", "error": "Twilio not configured"}
    
    twiml_message = (
        f'<Response>'
        f'<Say voice="alice" loop="3">Smoke Detected! Smoke Detected! '
        f'This is an emergency alert from Smoke Guard. '
        f'Smoke has been detected at location {gps_address}. '
        f'Please respond immediately.</Say>'
        f'<Pause length="2"/>'
        f'<Say voice="alice">If you received this message, the caller needs immediate assistance. '
        f'GPS coordinates: {gps_address}</Say>'
        f'</Response>'
    )
    
    try:
        call = twilio_client.calls.create(
            to=to_number,
            from_=from_number,
            twiml=twiml_message,
            timeout=30,
        )
        return {"status": "initiated", "call_sid": call.sid}
    except Exception as e:
        logger.error(f"Twilio call failed to {to_number}: {e}")
        return {"status": "failed", "error": str(e)}

def send_twilio_sms(to_number: str, gps_address: str, gps_lat: float, gps_lng: float):
    """Send SMS with smoke alert and GPS location."""
    twilio_client = get_twilio_client()
    from_number = os.environ.get("TWILIO_PHONE_NUMBER")
    
    if not twilio_client or not from_number:
        return
    
    message_body = (
        f"🚨 SMOKE DETECTED - Emergency Alert from Smoke Guard!\n\n"
        f"Smoke has been detected. Immediate attention required.\n\n"
        f"📍 GPS Location: {gps_address}\n"
        f"🗺 Maps: https://maps.google.com/?q={gps_lat},{gps_lng}\n\n"
        f"If the occupant does not respond, please call emergency services."
    )
    
    try:
        twilio_client.messages.create(
            to=to_number,
            from_=from_number,
            body=message_body,
        )
        logger.info(f"SMS sent to {to_number}")
    except Exception as e:
        logger.error(f"Twilio SMS failed to {to_number}: {e}")

async def run_call_sequence(alert_id: str):
    """Run real Twilio call sequence - calls contacts sequentially, sends SMS with GPS."""
    try:
        alert_doc = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
        user_id = alert_doc.get("user_id", "anonymous") if alert_doc else "anonymous"
        gps_address = alert_doc.get("gps_address", "Unknown location") if alert_doc else "Unknown"
        gps_lat = alert_doc.get("gps_lat", 0) if alert_doc else 0
        gps_lng = alert_doc.get("gps_lng", 0) if alert_doc else 0
        
        contacts = await db.contacts.find({"is_emt": False, "user_id": user_id}, {"_id": 0}).sort("order", 1).limit(5).to_list(5)
        emt = await db.contacts.find_one({"is_emt": True, "user_id": user_id}, {"_id": 0})
        all_targets = contacts + ([emt] if emt else [])
        
        for i, contact in enumerate(all_targets):
            alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
            if not alert or alert.get("status") in ("dismissed", "resolved"):
                return
            
            name = contact.get("name", f"Contact {i+1}")
            phone = contact.get("phone", "")
            is_emt_call = contact.get("is_emt", False)
            
            if not phone or phone == "Unknown":
                continue
            
            # Update status to ringing
            await db.alerts.update_one(
                {"id": alert_id},
                {"$set": {"current_call_index": i, "status": "calling"},
                 "$push": {"call_log": {"contact_name": name, "contact_phone": phone, "is_emt": is_emt_call, "status": "ringing", "timestamp": datetime.now(timezone.utc).isoformat()}}}
            )
            
            # Send SMS with GPS location
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, send_twilio_sms, phone, gps_address, gps_lat, gps_lng)
            
            # Make the actual call
            call_result = await loop.run_in_executor(None, make_twilio_call, phone, gps_address)
            
            if call_result.get("status") == "initiated":
                # Wait for call to be answered (poll for ~30 seconds)
                call_sid = call_result.get("call_sid")
                answered = False
                
                for _ in range(15):
                    await asyncio.sleep(2)
                    # Check if alert was dismissed
                    alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
                    if not alert or alert.get("status") in ("dismissed", "resolved"):
                        return
                    
                    # Check call status via Twilio
                    try:
                        twilio_client = get_twilio_client()
                        if twilio_client and call_sid:
                            call_info = twilio_client.calls(call_sid).fetch()
                            if call_info.status in ("in-progress", "completed"):
                                answered = True
                                break
                            elif call_info.status in ("canceled", "failed", "busy", "no-answer"):
                                break
                    except Exception as e:
                        logger.error(f"Error checking call status: {e}")
                
                # Update call log with result
                alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
                call_log = alert.get("call_log", []) if alert else []
                if call_log:
                    call_log[-1]["status"] = "answered" if answered else "no_answer"
                    call_log[-1]["call_sid"] = call_sid
                    await db.alerts.update_one({"id": alert_id}, {"$set": {"call_log": call_log}})
                
                if answered:
                    # Someone answered - mark alert as resolved
                    await db.alerts.update_one(
                        {"id": alert_id},
                        {"$set": {"status": "dismissed", "dismissed_by": "call_answered", "dismissed_at": datetime.now(timezone.utc).isoformat()}}
                    )
                    return
            else:
                # Call failed - mark as no_answer and continue
                alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
                call_log = alert.get("call_log", []) if alert else []
                if call_log:
                    call_log[-1]["status"] = "no_answer"
                    call_log[-1]["error"] = call_result.get("error", "")
                    await db.alerts.update_one({"id": alert_id}, {"$set": {"call_log": call_log}})
        
        # All calls done with no answer - mark as resolved
        await db.alerts.update_one({"id": alert_id}, {"$set": {"status": "resolved"}})
    except Exception as e:
        logger.error(f"Call sequence error for alert {alert_id}: {e}")
    finally:
        active_call_tasks.pop(alert_id, None)

@api_router.post("/alerts", response_model=AlertResponse)
async def create_alert(data: AlertCreate, request: Request):
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    
    await db.alerts.update_many(
        {"status": {"$in": ["alarm", "calling"]}},
        {"$set": {"status": "dismissed", "dismissed_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    alert = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "status": "alarm",
        "gps_lat": data.gps_lat,
        "gps_lng": data.gps_lng,
        "gps_address": data.gps_address,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dismissed_at": None,
        "dismissed_by": None,
        "current_call_index": -1,
        "call_log": [],
        "countdown_seconds": 180,
    }
    await db.alerts.insert_one(alert)
    alert.pop("_id", None)
    return AlertResponse(**alert)

@api_router.get("/alerts/active")
async def get_active_alert():
    alert = await db.alerts.find_one({"status": {"$in": ["alarm", "calling"]}}, {"_id": 0})
    if not alert:
        return {"active": False}
    return {"active": True, "alert": AlertResponse(**alert)}

@api_router.post("/alerts/{alert_id}/dismiss")
async def dismiss_alert(alert_id: str, dismissed_by: str = "user_button"):
    alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    await db.alerts.update_one(
        {"id": alert_id},
        {"$set": {"status": "dismissed", "dismissed_at": datetime.now(timezone.utc).isoformat(), "dismissed_by": dismissed_by}}
    )
    task = active_call_tasks.pop(alert_id, None)
    if task:
        task.cancel()
    return {"status": "dismissed", "alert_id": alert_id}

@api_router.post("/alerts/{alert_id}/start-calls")
async def start_calls(alert_id: str):
    alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    await db.alerts.update_one({"id": alert_id}, {"$set": {"status": "calling", "current_call_index": 0}})
    task = asyncio.create_task(run_call_sequence(alert_id))
    active_call_tasks[alert_id] = task
    return {"status": "calling_started", "alert_id": alert_id}

@api_router.get("/alerts/{alert_id}/call-status", response_model=CallStatusResponse)
async def get_call_status(alert_id: str):
    alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    idx = alert.get("current_call_index", -1)
    log = alert.get("call_log", [])
    name, phone = "", ""
    if log and idx >= 0:
        latest = log[-1]
        if latest.get("status") == "ringing":
            name = latest.get("contact_name", "")
            phone = latest.get("contact_phone", "")
    
    return CallStatusResponse(
        alert_id=alert_id, status=alert.get("status", "unknown"),
        current_call_index=idx, current_contact_name=name, current_contact_phone=phone,
        call_log=log, someone_answered=alert.get("dismissed_by") == "call_answered"
    )

@api_router.post("/alerts/{alert_id}/simulate-answer")
async def simulate_answer(alert_id: str):
    alert = await db.alerts.find_one({"id": alert_id}, {"_id": 0})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    log = alert.get("call_log", [])
    if log:
        log[-1]["status"] = "answered"
    
    await db.alerts.update_one(
        {"id": alert_id},
        {"$set": {"status": "dismissed", "dismissed_by": "call_answered", "dismissed_at": datetime.now(timezone.utc).isoformat(), "call_log": log}}
    )
    task = active_call_tasks.pop(alert_id, None)
    if task:
        task.cancel()
    return {"status": "answered", "alert_id": alert_id}

# ── Analytics Endpoints ─────────────────────────────────

@api_router.get("/analytics/history")
async def get_alert_history(request: Request):
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    
    alerts = await db.alerts.find(
        {"user_id": user_id}, {"_id": 0}
    ).sort("created_at", -1).to_list(50)
    
    return {"alerts": alerts, "total": len(alerts)}

@api_router.get("/analytics/stats")
async def get_stats(request: Request):
    user = await get_optional_user(request)
    user_id = user["_id"] if user else "anonymous"
    
    total = await db.alerts.count_documents({"user_id": user_id})
    dismissed = await db.alerts.count_documents({"user_id": user_id, "dismissed_by": "user_button"})
    call_answered = await db.alerts.count_documents({"user_id": user_id, "dismissed_by": "call_answered"})
    
    # Last 7 days
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent = await db.alerts.count_documents({
        "user_id": user_id,
        "created_at": {"$gte": week_ago.isoformat()}
    })
    
    return {
        "total_alerts": total,
        "dismissed_by_user": dismissed,
        "dismissed_by_call": call_answered,
        "alerts_last_7_days": recent,
        "subscription": user.get("subscription", "free") if user else "free",
    }

# ── Health ──────────────────────────────────────────────

@api_router.get("/")
async def root():
    return {"message": "Smoke Guard API", "status": "running"}

@api_router.get("/health")
async def health():
    return {"status": "healthy"}

# ── App Setup ───────────────────────────────────────────

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Serve Static Frontend (for Railway / production) ────
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

static_dir = ROOT_DIR / "static"
if static_dir.exists():
    # Serve static assets (JS, CSS, images)
    app.mount("/_expo", StaticFiles(directory=str(static_dir / "_expo")), name="expo_static")
    app.mount("/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets_static")
    
    # Serve favicon
    @app.get("/favicon.ico")
    async def favicon():
        fav = static_dir / "favicon.ico"
        if fav.exists():
            return FileResponse(str(fav))
        return Response(status_code=404)
    
    # Catch-all route: serve HTML pages for frontend routes
    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        # Skip API routes
        if path.startswith("api"):
            raise HTTPException(status_code=404, detail="Not found")
        
        # Try exact HTML file (e.g., /landing → landing.html)
        html_file = static_dir / f"{path}.html"
        if html_file.exists():
            return FileResponse(str(html_file), media_type="text/html")
        
        # Try path as directory with index.html
        index_file = static_dir / path / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file), media_type="text/html")
        
        # Try exact file (for any static file)
        exact_file = static_dir / path
        if exact_file.exists() and exact_file.is_file():
            return FileResponse(str(exact_file))
        
        # Default: serve landing page for root, index.html for everything else
        if path == "" or path == "/":
            landing = static_dir / "landing.html"
            if landing.exists():
                return FileResponse(str(landing), media_type="text/html")
        
        # Fallback to index.html (SPA routing)
        fallback = static_dir / "index.html"
        if fallback.exists():
            return FileResponse(str(fallback), media_type="text/html")
        
        raise HTTPException(status_code=404, detail="Not found")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup():
    try:
        await db.users.create_index("email", unique=True)
        await db.login_attempts.create_index("identifier")
        
        # Setup Stripe recurring products/prices
        await ensure_stripe_products()
        
        # Seed admin
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@smokeguard.com")
        admin_password = os.environ.get("ADMIN_PASSWORD", "SmokeSafe2024!")
        existing = await db.users.find_one({"email": admin_email})
        if not existing:
            await db.users.insert_one({
                "email": admin_email,
                "password_hash": hash_password(admin_password),
                "name": "Admin",
                "role": "admin",
                "subscription": "pro",
                "subscription_expires": datetime.now(timezone.utc) + timedelta(days=365),
                "created_at": datetime.now(timezone.utc),
            })
            logger.info(f"Admin seeded: {admin_email}")
        elif not verify_password(admin_password, existing["password_hash"]):
            await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}})
            logger.info("Admin password updated")
    except Exception as e:
        logger.error(f"Startup error (non-fatal): {e}")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
