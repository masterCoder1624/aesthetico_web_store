import time
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List
import passlib.hash as hash
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# --- Security & JWT Configuration ---
SECRET_KEY = "a_very_secret_key_that_should_be_in_an_env_file"
ALGORITHM = "HS265"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# --- In-Memory Databases ---
fake_users_db = {}
fake_products_db = [
    {
        "id": "prod_1",
        "title": "sundar si kitaab",
        "price_inr": 149,
        "image_url": "https://m.media-amazon.com/images/I/61uWK0fA20L._UF1000,1000_QL80_.jpg",
        "long_description": "A beautifully crafted journal with a vintage butterfly cover. Features 200 pages of high-quality, acid-free paper, perfect for writing, sketching, or dreaming. The lay-flat binding makes it a joy to use."
    },
    {
        "id": "prod_2",
        "title": "pariyo ki rani",
        "price_inr": 249,
        "image_url": "https://placehold.co/600x800/d1d5db/1f2937?text=Rustic+Feather",
        "long_description": "Embrace your inner wanderer with this pack of 10 digital papers featuring rustic feather designs. Each design is unique and high-resolution, ideal for scrapbooking, card making, or as a background for your digital journal."
    },
    {
        "id": "prod_3",
        "title": "meri jeevan kathaa",
        "price_inr": 199,
        "image_url": "https://placehold.co/600x800/fecaca/991b1b?text=Floral+Dreams",
        "long_description": "Bring your journal to life with these printable pages adorned with delicate floral patterns. This digital download includes 5 unique A4 designs that you can print as many times as you like. Perfect for bullet journaling and daily planning."
    }
]

# --- Pydantic Models ---
class Product(BaseModel):
    id: str
    title: str
    price_inr: int
    image_url: str
    long_description: str

class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str

class TokenData(BaseModel):
    email: str | None = None

# --- FastAPI App Instance ---
app = FastAPI()

# --- CORS Middleware ---
# This section is updated to be more explicit for better compatibility.
origins = [
    "null",
    "http://localhost",
    "http://localhost:8080",
    "https://aesthetica-web-store-frontend.onrender.com",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"], # Explicitly allow OPTIONS
    allow_headers=["*"], # Allow all headers
)

# --- Helper Functions ---
def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": time.time() + ACCESS_TOKEN_EXPIRE_MINUTES * 60})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Welcome to the Aesthetic Notebooks API! Now with products."}

@app.get("/api/products", response_model=List[Product])
def get_products():
    return fake_products_db

@app.get("/api/products/{product_id}", response_model=Product)
def get_product_by_id(product_id: str):
    for product in fake_products_db:
        if product["id"] == product_id:
            return product
    raise HTTPException(status_code=404, detail="Product not found")

@app.post("/api/auth/register")
def register_user(user: UserCreate):
    if user.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = hash.bcrypt.hash(user.password)
    fake_users_db[user.email] = {"full_name": user.full_name, "hashed_password": hashed_password}
    return {"message": "User registered successfully"}

@app.post("/api/auth/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username
    user = fake_users_db.get(email)
    if not user or not hash.bcrypt.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": email, "full_name": user.get("full_name", "")})
    return {"access_token": access_token, "token_type": "bearer", "user": {"email": email, "full_name": user.get("full_name", "")}}

