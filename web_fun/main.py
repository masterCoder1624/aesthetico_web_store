# --- main.py (No Database Version with Products) ---

# --- 1. Imports ---
import uuid
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
# NEW: Import for CORS
from fastapi.middleware.cors import CORSMiddleware

# --- 2. Configuration & Setup ---

# Initialize FastAPI app
app = FastAPI(title="Aesthetic Notebooks API (No DB)")

# NEW: Add CORS Middleware
# This allows our frontend (index.html) to communicate with this backend.
origins = [
    "null", # Allows local file access (opening index.html directly)
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory "database" to store user and product data.
fake_users_db = {}

# NEW: In-memory product database
fake_products_db = [
    {
        "id": "prod_1",
        "title": "sundar si kitaab",
        "price_inr": 149,
        "image_url": "https://m.media-amazon.com/images/I/61uWK0fA20L._UF1000,1000_QL80_.jpg"
    },
    {
        "id": "prod_2",
        "title": "pariyo ki rani",
        "price_inr": 249,
        "image_url": "https://placehold.co/600x800/d1d5db/1f2937?text=Rustic+Feather"
    },
    {
        "id": "prod_3",
        "title": "meri jeevan kathaa",
        "price_inr": 199,
        "image_url": "https://placehold.co/600x800/fecaca/991b1b?text=Floral+Dreams"
    }
]

# Security setup
SECRET_KEY = "a_very_secret_key_for_demonstration"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# --- 3. Pydantic Models (Data Shapes) ---

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserInDB(BaseModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str
    role: str
    is_verified: bool
    password_hash: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: EmailStr | None = None
    
# NEW: Product model
class Product(BaseModel):
    id: str
    title: str
    price_inr: int
    image_url: str

# --- 4. Helper Functions (Unchanged) ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- 5. API Endpoints ---

@app.get("/")
def read_root():
    return {"message": "Welcome to the Aesthetic Notebooks API! Now with products."}
    
# --- NEW: PRODUCTS ENDPOINT ---
@app.get("/api/products", response_model=list[Product])
async def get_products():
    """
    Returns the list of featured products from the in-memory store.
    """
    return fake_products_db

# --- AUTHENTICATION ENDPOINTS (Unchanged) ---

@app.post("/api/auth/register", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate):
    if user.email in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    hashed_password = get_password_hash(user.password)
    user_id = uuid.uuid4()
    new_user = UserInDB(
        id=user_id, email=user.email, full_name=user.full_name,
        password_hash=hashed_password, role="customer", is_verified=False
    )
    fake_users_db[user.email] = new_user.dict()
    return new_user

@app.post("/api/auth/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- 6. How to Run ---
# uvicorn main:app --reload

