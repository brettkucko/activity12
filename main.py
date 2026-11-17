import os
from datetime import datetime, timedelta, timezone

import bcrypt
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# ======== ENV / CONFIG ========
load_dotenv()
MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "MobileApp")
PORT = int(os.getenv("PORT", "8000"))
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is not set")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set")

client = MongoClient(MONGODB_URI)
db = client[MONGODB_DB]
users_collection = db["users"]
users_collection.create_index("email", unique=True)  # prevents duplicate signups
robots_collection = db["robots"]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # restrict to your frontend domain in production
    allow_credentials=False,    # must be False with wildcard origins
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======== MODELS ========
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)  # bcrypt limit

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class Robot(BaseModel):
    name: str
    price: float
    description: str
    imageUrl: str

# ======== HELPERS ========
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False

def create_jwt_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(email: str):
    user = users_collection.find_one({"email": email.lower()})
    if not user:
        return None
    return {"email": user["email"], "hashed_password": user["hashed_password"]}

def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    email = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    if get_user_by_email(email) is None:
        raise HTTPException(status_code=401, detail="User not found")
    return email

# ======== AUTH ROUTES ========
@app.post("/signup")
def signup(user: UserCreate):
    email = user.email.lower()
    try:
        users_collection.insert_one(
            {"email": email, "hashed_password": hash_password(user.password)}
        )
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="User already exists")
    return {"msg": "signup ok"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db_user = get_user_by_email(form_data.username)
    if not db_user or not verify_password(form_data.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt_token({"sub": db_user["email"]})
    return {"access_token": token, "token_type": "bearer"}

# ======== GENERAL ROUTES ========
@app.get("/protected")
def read_protected_data(current_user: str = Depends(get_current_user)):
    return {"msg": f"Hello {current_user}, this is protected data!"}

@app.get("/hello")
def hello():
    return {"message": "Hello from FastAPI!"}

# ======== ROBOTS ========
@app.get("/robots")
def get_robots():
    robots = list(robots_collection.find())
    for r in robots:
        r["_id"] = str(r["_id"])
    return robots

@app.post("/robots")
def add_robot(robot: Robot, current_user: str = Depends(get_current_user)):
    robots_collection.insert_one(robot.model_dump())
    return {"message": "Robot added successfully"}
