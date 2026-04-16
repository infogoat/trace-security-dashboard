from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.user import User
from app.schemas.user_schema import UserCreate, UserLogin
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
)
import re

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):

    password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$"

    if not re.match(password_regex, user.password):
    	raise HTTPException(
        	status_code=400,
        	detail="Password must contain at least one uppercase, one lowercase, one digit and be minimum 6 characters long."
    )

    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    role = user.role if user.role else "user"

    # HARD CONTROL
    if user.username == "admin":
        role = "admin"
    
    new_user = User(
        username=user.username,
        password=hash_password(user.password),
        role=role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}

@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(
    data={
        "sub": user.username,
        "role": user.role
    }
	)
    return {
    "access_token": access_token,
    "token_type": "bearer",
    "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }
@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role
    }
