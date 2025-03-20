from fastapi import FastAPI, HTTPException, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from models import Chat, User, Msg, user_chat_table, chat_msg_table  # Assuming models.py contains SQLAlchemy models
from database import get_db  # A function to get a database session
import os
from dotenv import load_dotenv
from pydantic import BaseModel

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

class SignUpInfo(BaseModel):
    username: str
    pswd: str
    email: str

class LoginInfo(BaseModel):
    username: str
    pswd: str

class SendingNewMsg(BaseModel):
    chat_id: str
    text_content: str
    media_content: str
    sender: str

load_dotenv()

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(debug=True)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allow all headers
)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=ALGORITHM)

def to_dict(obj):
    """Helper function to convert SQLAlchemy model to dictionary."""
    return {column.name: getattr(obj, column.name) for column in obj.__table__.columns}

@app.middleware("http")
async def validate_token_middleware(request: Request, call_next):
    if request.url.path in ["/signup", "/login"]:
        return await call_next(request)
    
    token = None

    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    
    # If token not found in headers, check in cookies
    if not token:
        token = request.cookies.get("access_token")
        if token and token.startswith("Bearer "):
            token = token.split(" ")[1]

    if token:
        try:
            payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[ALGORITHM])
            user_id = payload.get("user_id")
            
            # Check if user exists in DB
            db: Session = next(get_db())  # Get a database session
            user = db.query(User).filter(User.user_id == user_id).first()
            
            if not user:
                raise HTTPException(status_code=401, detail="Invalid token: User does not exist")
            
            # Attach user to request state
            request.state.user = user

        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    response = await call_next(request)
    return response

@app.post("/signup")
def signup(userInfo: SignUpInfo, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(userInfo.pswd)
    new_user = User(username=userInfo.username, email=userInfo.email, password=hashed_password)

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        print('Error not caught')
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400,detail="Username or Email already used")
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400,content="Request Failed")

    access_token = create_access_token(data={'sub':str(new_user.user_id)})

    response = JSONResponse(content={"access_token": access_token,"message": "User created successfully"})
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

@app.post("/login")
def login(userInfo: LoginInfo, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == userInfo.username).first()
    if not user or not pwd_context.verify(userInfo.pswd, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"user_id":str(user.user_id)})
    response = JSONResponse(content={"access_token": access_token, "message": "User Login Successful"})
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

@app.post("/logout")
def logout():
    JSONResponse().delete_cookie("access_token")
    return {"message": "Logout successful"}

@app.get("/chats")
def fetchChats(request: Request, db: Session = Depends(get_db)):
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = request.state.user

    try:
        chats = (
            db.query(Chat)
            .join(user_chat_table, Chat.chat_id == user_chat_table.c.chat_id)
            .filter(user_chat_table.c.user_id == user.user_id)
            .order_by(Chat.created_on.desc())
            .all()
        )

        return chats
    
    except Exception as e:
        raise HTTPException(status_code=400,detail=str(e))
    

@app.get('/msgs/{chat_id}')
def fetchMsgs(chat_id: str, db: Session = Depends(get_db)):
    try:
        msgs = (
            db.query(Msg)
            .join(chat_msg_table, Msg.msg_id == chat_msg_table.c.msg_id)
            .filter(chat_msg_table.c.chat_id == chat_id)
            .all()
        )

    except Exception as e:
        raise HTTPException(status_code=400,detail=str(e))
    
    return msgs
       

@app.post('/sendMsg')
def sendMsg(body: SendingNewMsg, request: Request, db: Session = Depends(get_db)):
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = request.state.user

    if(body.chat_id == ''):
        chat = Chat(title="New Chat") # add mistral here
        
        try:
            db.add(chat)
            db.commit()
            db.refresh(chat)

            db.execute(user_chat_table.insert().values(user_id=user.user_id, chat_id=chat.chat_id))
            db.commit()
        except Exception as er:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(er))
    
    new_msg = Msg(sender=body.sender,text_content=body.text_content,media_content=body.media_content)

    try:
        db.add(new_msg)
        db.commit()
        db.refresh(new_msg)

        if(body.chat_id==''):
            db.execute(chat_msg_table.insert().values(
                chat_id = chat.chat_id,
                msg_id = new_msg.msg_id
            ))
            db.commit()
        else:
            db.execute(chat_msg_table.insert().values(
                chat_id = body.chat_id,
                msg_id = new_msg.msg_id
            ))
            db.commit()

            old_chat = db.query(Chat).filter(Chat.chat_id == body.chat_id).first()

        
        return {'msg':to_dict(new_msg),'chat':to_dict(chat) if body.chat_id=='' else to_dict(old_chat)}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f'Error: {e}')
