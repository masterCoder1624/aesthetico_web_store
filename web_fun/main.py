import os
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
import passlib.hash as hash
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Security & JWT Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"  # Fixed typo: was HS265
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# --- In-Memory Databases ---
fake_users_db = {}

# UPDATED: Replaced placeholder URLs with the new image URLs
# Convert to dictionary for O(1) lookup performance
fake_products_db = {
    "prod_1": {
        "id": "prod_1",
        "title": "sundar si kitaab",
        "price_inr": 149,
        "image_url": "https://tse1.mm.bing.net/th/id/OIP.9_J-OP2Dt0PTGXwdZ5dLQAHaJf?cb=12&rs=1&pid=ImgDetMain&o=7&rm=3",
        "long_description": "A beautifully crafted journal with a vintage butterfly cover. Features 200 pages of high-quality, acid-free paper, perfect for writing, sketching, or dreaming. The lay-flat binding makes it a joy to use."
    },
    "prod_2": {
        "id": "prod_2",
        "title": "pariyo ki rani",
        "price_inr": 249,
        "image_url": "https://i5.walmartimages.com/asr/c1982ebe-ffc0-446f-bf67-106736033c24.2e3d829a1e58ef44a775fa3b9dbfb377.jpeg?odnWidth=1000&odnHeight=1000&odnBg=ffffff",
        "long_description": "Embrace your inner wanderer with this pack of 10 digital papers featuring rustic feather designs. Each design is unique and high-resolution, ideal for scrapbooking, card making, or as a background for your digital journal."
    },
    "prod_3": {
        "id": "prod_3",
        "title": "meri jeevan kathaa",
        "price_inr": 199,
        "image_url": "https://m.media-amazon.com/images/I/81HZ4rCrm6L._SL1500_.jpg",
        "long_description": "Bring your journal to life with these printable pages adorned with delicate floral patterns. This digital download includes 5 unique A4 designs that you can print as many times as you like. Perfect for bullet journaling and daily planning."
    },
    "prod_4": {
        "id": "prod_4",
        "title": "Celestial Dreams Journal",
        "price_inr": 299,
        "image_url": "https://tse2.mm.bing.net/th/id/OIP.FEqlMvOaXSHSX3XFgwifggHaF7?cb=12&rs=1&pid=ImgDetMain&o=7&rm=3",
        "long_description": "Capture the magic of the night sky with this elegant journal. Featuring a deep navy cover with gold foil constellations, it's the perfect companion for stargazers and dreamers alike. Contains 180 dotted pages."
    },
    "prod_5": {
        "id": "prod_5",
        "title": "Minimalist Grid Notebook",
        "price_inr": 189,
        "image_url": "https://idcreativedesign.co.uk/wp-content/uploads/2023/01/NGSW_printdesign_diaries.jpg",
        "long_description": "For the organized mind, this minimalist notebook features a clean grid layout on every page. Its simple, functional design makes it ideal for note-taking, architectural sketches, or habit tracking. Available in A5 size."
    },
    "prod_6": {
        "id": "prod_6",
        "title": "Forest Wanderer's Log",
        "price_inr": 229,
        "image_url": "https://m.media-amazon.com/images/I/71J1ThweunS.jpg",
        "long_description": "A rustic, durable notebook designed for adventurers. The cover features an embossed pine tree, and its water-resistant pages are perfect for jotting down notes and observations on your travels through nature."
    },
    "prod_7": {
        "id": "prod_7",
        "title": "Ocean Depths Diary",
        "price_inr": 219,
        "image_url": "https://placehold.co/600x800/bae6fd/0c4a6e?text=Ocean+Depths",
        "long_description": "Dive into your thoughts with the Ocean Depths Diary. Its cover showcases a mesmerizing watercolor design of marine life. Contains lined pages made from recycled materials, perfect for the eco-conscious writer."
    },
    "prod_8": {
        "id": "prod_8",
        "title": "Abstract Geometry Pack",
        "price_inr": 279,
        "image_url": "https://placehold.co/600x800/fde68a/b45309?text=Abstract+Geo",
        "long_description": "A vibrant collection of 12 digital papers featuring bold, abstract geometric patterns. Perfect for adding a modern touch to your digital planners, presentations, or creative projects. High-resolution JPG files included."
    },
    "prod_9": {
        "id": "prod_9",
        "title": "Gilded Age Pages",
        "price_inr": 179,
        "image_url": "https://placehold.co/600x800/fef9c3/78350f?text=Gilded+Age",
        "long_description": "Add a touch of vintage elegance to your work with these printable pages. Featuring ornate, gilded borders and a classic cream background, they are perfect for invitations, certificates, or formal letter writing. PDF format."
    }
}

# --- Pydantic Models ---
class Product(BaseModel):
    id: str = Field(..., description="Unique product identifier")
    title: str = Field(..., min_length=1, max_length=100, description="Product title")
    price_inr: int = Field(..., gt=0, description="Price in Indian Rupees")
    image_url: str = Field(..., description="Product image URL")
    long_description: str = Field(..., min_length=10, max_length=1000, description="Detailed product description")

class UserCreate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=50, description="User's full name")
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, max_length=50, description="User's password")

class UserResponse(BaseModel):
    email: str
    full_name: str

class TokenData(BaseModel):
    email: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class MessageResponse(BaseModel):
    message: str

# --- Utility Functions ---
def create_access_token(data: dict) -> str:
    """Create a JWT access token with expiration."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> TokenData:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return TokenData(email=email)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Get the current authenticated user."""
    token_data = verify_token(token)
    user = fake_users_db.get(token_data.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"email": token_data.email, "full_name": user.get("full_name", "")}

# --- FastAPI App Instance ---
app = FastAPI(
    title="Aesthetic Notebooks API",
    description="A beautiful API for managing aesthetic notebooks and journals",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# --- CORS Middleware ---
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:8080",
    "https://aesthetica-web-store-frontend.onrender.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# --- API Endpoints ---
@app.get("/", response_model=MessageResponse)
async def read_root():
    """Welcome endpoint with API information."""
    logger.info("Root endpoint accessed")
    return MessageResponse(message="Welcome to the Aesthetic Notebooks API! Now with 9 products.")

@app.get("/api/products", response_model=List[Product])
async def get_products():
    """Get all available products."""
    logger.info("Products endpoint accessed")
    return list(fake_products_db.values())

@app.get("/api/products/{product_id}", response_model=Product)
async def get_product_by_id(product_id: str):
    """Get a specific product by ID."""
    logger.info(f"Product lookup requested for ID: {product_id}")
    
    if product_id not in fake_products_db:
        logger.warning(f"Product not found: {product_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"Product with ID '{product_id}' not found"
        )
    
    return fake_products_db[product_id]

@app.post("/api/auth/register", response_model=MessageResponse)
async def register_user(user: UserCreate):
    """Register a new user."""
    logger.info(f"Registration attempt for email: {user.email}")
    
    if user.email in fake_users_db:
        logger.warning(f"Registration failed - email already exists: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email already registered"
        )
    
    try:
        hashed_password = hash.bcrypt.hash(user.password)
        fake_users_db[user.email] = {
            "full_name": user.full_name, 
            "hashed_password": hashed_password
        }
        logger.info(f"User registered successfully: {user.email}")
        return MessageResponse(message="User registered successfully")
    except Exception as e:
        logger.error(f"Registration error for {user.email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to server error"
        )

@app.post("/api/auth/token", response_model=TokenResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return access token."""
    email = form_data.username
    logger.info(f"Login attempt for email: {email}")
    
    user = fake_users_db.get(email)
    if not user or not hash.bcrypt.verify(form_data.password, user["hashed_password"]):
        logger.warning(f"Login failed for email: {email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        access_token = create_access_token(
            data={"sub": email, "full_name": user.get("full_name", "")}
        )
        logger.info(f"Login successful for email: {email}")
        return TokenResponse(
            access_token=access_token, 
            token_type="bearer", 
            user=UserResponse(email=email, full_name=user.get("full_name", ""))
        )
    except Exception as e:
        logger.error(f"Token creation error for {email}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed due to server error"
        )

@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information."""
    logger.info(f"User info requested for: {current_user['email']}")
    return UserResponse(email=current_user["email"], full_name=current_user["full_name"])
