from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import Dict, Optional
from datetime import datetime, timedelta
import random
import string
import smtplib
from email.mime.text import MIMEText #MIME TEXT MEANS MIME MESSAGE
# MIME STANDS FOR MULTIPART INTERNET MAIL EXCHANGE
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI(title="Email OTP Authentication")

# In-memory storage for OTPs and user sessions
# In production, you would use a database
otp_store: Dict[str, Dict] = {}
user_sessions: Dict[str, Dict] = {}

# Email configuration - replace with your own SMTP details
EMAIL_HOST =    os.getenv("EMAIL_HOST")
EMAIL_PORT =    os.getenv("EMAIL_PORT")
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class EmailRequest(BaseModel):
    email: EmailStr

class OTPVerification(BaseModel):
    email: EmailStr
    otp: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

def generate_otp(length=6):
    """Generate a random OTP of specified length"""
    return ''.join(random.choices(string.digits, k=length))

def send_email(to_email: str, otp: str):
    """Send OTP via email"""
    message = MIMEMultipart()
    message["From"] = EMAIL_FROM
    message["To"] = to_email
    message["Subject"] = "Your OTP Code"
    
    body = f"""
    <html>
    <body>
        <h2>Your One-Time Password</h2>
        <p>Your OTP code is: <strong>{otp}</strong></p>
        <p>This code will expire in 10 minutes.</p>
    </body>
    </html>
    """
    
    message.attach(MIMEText(body, "html"))
    
    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        # start TLS encryption (tls stands for transport layer security)
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        # log in using the email username and password
        server.sendmail(EMAIL_FROM, to_email, message.as_string())
        # send the email
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def generate_session_token():
    """Generate a random session token"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Validate the current user's session token"""
    if token not in user_sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    session = user_sessions[token]
    if datetime.now() > session["expires_at"]:
        del user_sessions[token]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return session["email"]

@app.post("/send-otp", status_code=status.HTTP_200_OK)
async def send_otp(email_request: EmailRequest):
    """Send OTP to the provided email"""
    email = email_request.email
    otp = generate_otp()
    
    # Store OTP with expiration time (10 minutes)
    expiration_time = datetime.now() + timedelta(minutes=10)
    otp_store[email] = {
        "otp": otp,
        "expires_at": expiration_time
    }
    
    # Send OTP via email
    if not send_email(email, otp):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP email"
        )
    
    return {"message": "OTP sent successfully", "expires_at": expiration_time}

@app.post("/verify-otp", response_model=TokenResponse)
async def verify_otp(verification: OTPVerification):
    """Verify OTP and create user session"""
    email = verification.email
    
    if email not in otp_store:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No OTP was requested for this email"
        )
    
    otp_data = otp_store[email]
    current_time = datetime.now()
    
    # Check if OTP has expired
    if current_time > otp_data["expires_at"]:
        del otp_store[email]  # Clean up expired OTP
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP has expired, please request a new one"
        )
    
    # Verify OTP
    if verification.otp != otp_data["otp"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP"
        )
    
    # OTP verified, clean up OTP data
    del otp_store[email]
    
    # Create user session with 1 hour expiration
    session_token = generate_session_token()
    user_sessions[session_token] = {
        "email": email,
        "expires_at": current_time + timedelta(hours=1)
    }
    
    return {"access_token": session_token, "token_type": "bearer"}

@app.get("/me")
async def get_user_info(current_user: str = Depends(get_current_user)):
    """Get information about the authenticated user"""
    return {"email": current_user}

@app.post("/logout")
async def logout(current_user: str = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    """Log out the current user by invalidating their session token"""
    if token in user_sessions:
        del user_sessions[token]
    
    return {"message": "Logged out successfully"}

# Periodic cleanup of expired OTPs and sessions
# In a production environment, you would use a task scheduler or cron job
@app.on_event("startup")
async def startup_event():
    print("Starting up FastAPI application...")

@app.get("/")
async def root():
    return {"message": "Email OTP Authentication API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)