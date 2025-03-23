from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from jose import JWTError, jwt
from models import Chat, User, Msg, user_chat_table, chat_msg_table, VideoProject 
from database import get_db
import os
import requests
import json
import asyncio
from dotenv import load_dotenv
from pydantic import BaseModel
import pusher
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

from mistral_util import msgs, mistral_client, formatMsg

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

class TopicRequest(BaseModel):
    topic: str

class VideoGenerationRequest(BaseModel):
    video_project_id: str
    include_narration: bool = True

class PromptUpdateRequest(BaseModel):
    video_project_id: str
    scene_prompts: list[str]
    audio_prompts: list[str]

load_dotenv()


AI_BACKEND_URL = "http://184.72.131.74:8080"


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pusher_client = pusher.Pusher(
    app_id=os.getenv('PUSHER_APP_ID', ''),
    key=os.getenv('PUSHER_KEY', ''),
    secret=os.getenv('PUSHER_SECRET', ''),
    cluster=os.getenv('PUSHER_CLUSTER', 'us2'),
    ssl=True
)

app = FastAPI(debug=True)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


VIDEOS_DIR = os.path.join(os.getcwd(), "videos")
os.makedirs(VIDEOS_DIR, exist_ok=True)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=ALGORITHM)

def to_dict(obj):
    """Helper function to convert SQLAlchemy model to dictionary."""
    return {column.name: getattr(obj, column.name) for column in obj.__table__.columns}

def send_update(video_project_id, event, data):
    """Send real-time update via Pusher"""
    try:
        pusher_client.trigger(f'video-project-{video_project_id}', event, data)
    except Exception as e:
        print(f"Pusher error: {e}")


@app.middleware("http")
async def validate_token_middleware(request: Request, call_next):
    skip_auth_paths = ["/signup", "/login", "/videos/"]
    for path in skip_auth_paths:
        if request.url.path.startswith(path):
            return await call_next(request)
    
    token = None

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    
    if not token:
        token = request.cookies.get("access_token")
        if token and token.startswith("Bearer "):
            token = token.split(" ")[1]

    if token:
        try:
            payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[ALGORITHM])
            user_id = payload.get("user_id")
            

            db: Session = next(get_db()) 
            user = db.query(User).filter(User.user_id == user_id).first()
            
            if not user:
                raise HTTPException(status_code=401, detail="Invalid token: User does not exist")
            

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
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400,detail="Username or Email already used")
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400,content="Request Failed")

    access_token = create_access_token(data={'user_id':str(new_user.user_id)})

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
    response = JSONResponse(content={"message": "Logout successful"})
    response.delete_cookie("access_token")
    return response


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
        msgs.append(formatMsg(f'Message: "{body.text_content}"\nText: '))
        resp = mistral_client.chat(model="mistral-small",messages=msgs)
        print(resp.choices[0].message.content)
        msgs.pop()
        chat = Chat(title=resp.choices[0].message.content.strip('"')) 
        
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
        db.rollback()
        raise HTTPException(status_code=400, detail=f'Error: {e}')


async def generate_video_prompts(topic: str, video_project_id: str):
    """Call the remote backend to generate prompts"""
    try:
        send_update(video_project_id, "status_update", {"message": "Generating prompts..."})

        response = requests.post(
            f"{AI_BACKEND_URL}/generate-prompts",
            json={"topic": topic, "session_id": video_project_id}
        )
        
        if response.status_code != 200:
            error_message = f"Backend error: {response.text}"
            send_update(video_project_id, "error", {"message": error_message})
            return None
        
        return response.json()
    except Exception as e:
        send_update(video_project_id, "error", {"message": f"Error connecting to AI backend: {str(e)}"})
        return None

async def generate_videos_remote(video_project_id: str):
    """Call the remote backend to generate videos"""
    try:
        send_update(video_project_id, "status_update", {"message": "Starting video generation..."})

        response = requests.post(
            f"{AI_BACKEND_URL}/generate-videos",
            json={"session_id": video_project_id}
        )
        
        if response.status_code != 200:
            error_message = f"Backend error: {response.text}"
            send_update(video_project_id, "error", {"message": error_message})
            return False
        
        return True
    except Exception as e:
        send_update(video_project_id, "error", {"message": f"Error connecting to AI backend: {str(e)}"})
        return False

async def combine_videos_remote(video_project_id: str, include_narration: bool):
    """Call the remote backend to combine videos"""
    try:
        send_update(video_project_id, "status_update", {"message": "Combining videos..."})
        
        response = requests.post(
            f"{AI_BACKEND_URL}/combine-videos",
            json={"session_id": video_project_id, "include_narration": include_narration}
        )
        
        if response.status_code != 200:
            error_message = f"Backend error: {response.text}"
            send_update(video_project_id, "error", {"message": error_message})
            return False
        
        return True
    except Exception as e:
        send_update(video_project_id, "error", {"message": f"Error connecting to AI backend: {str(e)}"})
        return False

async def poll_session_status(video_project_id: str, db: Session):
    """Continuously poll the AI backend for status updates"""
    try:
        max_attempts = 200 
        attempts = 0
        
        while attempts < max_attempts:
            attempts += 1
            

            response = requests.get(f"{AI_BACKEND_URL}/session/{video_project_id}")
            
            if response.status_code != 200:
                if attempts % 10 == 0:  
                    send_update(video_project_id, "status_update", 
                              {"message": f"Still waiting for backend... (attempt {attempts})"})
                await asyncio.sleep(3)
                continue
            
            data = response.json()
            
            project = db.query(VideoProject).filter(VideoProject.video_project_id == video_project_id).first()
            if project:
                if 'scene_prompts' in data and data['scene_prompts']:
                    project.scene_prompts = json.dumps(data['scene_prompts'])
                    send_update(video_project_id, "prompts_ready", {"scene_prompts": data['scene_prompts']})
                
                if 'audio_prompts' in data and data['audio_prompts']:
                    project.audio_prompts = json.dumps(data['audio_prompts'])
                    send_update(video_project_id, "audio_prompts_ready", {"audio_prompts": data['audio_prompts']})
                
                if 'video_urls' in data and data['video_urls']:
                    project.remote_video_urls = json.dumps(data['video_urls'])
                    project.status = "videos_ready"
                    send_update(video_project_id, "videos_ready", {"urls": data['video_urls']})
                
                if 'has_combined_video' in data and data['has_combined_video']:
                    project.status = "complete"
                    project.remote_combined_url = data.get('combined_video_url', '')
                    send_update(video_project_id, "combined_complete", {
                        "url": project.remote_combined_url
                    })
                    db.commit()
                    break 
                
                db.commit()
            
            await asyncio.sleep(5) 
        
        if attempts >= max_attempts:
            send_update(video_project_id, "error", {"message": "Polling timeout - please check backend status"})
    
    except Exception as e:
        send_update(video_project_id, "error", {"message": f"Error polling backend: {str(e)}"})
        project = db.query(VideoProject).filter(VideoProject.video_project_id == video_project_id).first()
        if project:
            project.status = "error"
            project.error_message = str(e)
            db.commit()



@app.post("/api/generate-video-prompts")
async def create_video_project(request: Request, topic_request: TopicRequest, 
                       background_tasks: BackgroundTasks,
                       db: Session = Depends(get_db)):
    """
    Create a new video project and generate prompts for it
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = request.state.user
    
  
    video_project_id = str(uuid4())
    new_project = VideoProject(
        video_project_id=video_project_id,
        user_id=user.user_id,
        topic=topic_request.topic,
        status="initializing",
        created_at=datetime.now()
    )
    
    try:
        db.add(new_project)
        db.commit()
        db.refresh(new_project)
        

        background_tasks.add_task(generate_video_prompts, topic_request.topic, video_project_id)
        
        background_tasks.add_task(poll_session_status, video_project_id, db)
        
        return {
            "video_project_id": video_project_id, 
            "status": "initializing",
            "topic": topic_request.topic
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/update-prompts")
async def update_prompts(request: Request, prompt_update: PromptUpdateRequest, db: Session = Depends(get_db)):
    """
    Update the scene and audio prompts for a video project
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = request.state.user
    

    project = db.query(VideoProject).filter(
        VideoProject.video_project_id == prompt_update.video_project_id,
        VideoProject.user_id == user.user_id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        project.scene_prompts = json.dumps(prompt_update.scene_prompts)
        project.audio_prompts = json.dumps(prompt_update.audio_prompts)
        db.commit()
        

        response = requests.post(
            f"{AI_BACKEND_URL}/update-prompts",
            json={
                "session_id": prompt_update.video_project_id,
                "scene_prompts": prompt_update.scene_prompts,
                "audio_prompts": prompt_update.audio_prompts
            }
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Error updating prompts on backend")
        
        return {
            "video_project_id": project.video_project_id,
            "status": "prompts_updated"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/generate-videos")
async def generate_videos(request: Request, video_request: VideoGenerationRequest, 
                   background_tasks: BackgroundTasks,
                   db: Session = Depends(get_db)):
    """
    Start generating videos for a project
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = request.state.user
    

    project = db.query(VideoProject).filter(
        VideoProject.video_project_id == video_request.video_project_id,
        VideoProject.user_id == user.user_id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if not project.scene_prompts:
        raise HTTPException(status_code=400, detail="No prompts available for video generation")
    

    project.status = "generating_videos"
    db.commit()
    

    background_tasks.add_task(generate_videos_remote, video_request.video_project_id)
    
    return {
        "video_project_id": project.video_project_id,
        "status": "generating_videos"
    }

@app.post("/api/combine-videos")
async def combine_videos(request: Request, video_request: VideoGenerationRequest, 
                  background_tasks: BackgroundTasks,
                  db: Session = Depends(get_db)):
    """
    Combine individual videos into one final video
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = request.state.user
    

    project = db.query(VideoProject).filter(
        VideoProject.video_project_id == video_request.video_project_id,
        VideoProject.user_id == user.user_id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if not project.remote_video_urls:
        raise HTTPException(status_code=400, detail="No videos available for combining")
    

    project.status = "combining_videos"
    db.commit()
    
   
    background_tasks.add_task(combine_videos_remote, video_request.video_project_id, 
                             video_request.include_narration)
    
    return {
        "video_project_id": project.video_project_id,
        "status": "combining_videos"
    }

@app.get("/api/video-projects")
async def get_video_projects(request: Request, db: Session = Depends(get_db)):
    """
    Get all video projects for the current user
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = request.state.user
    
    projects = db.query(VideoProject).filter(
        VideoProject.user_id == user.user_id
    ).order_by(VideoProject.created_at.desc()).all()
    
    result = []
    for project in projects:
        project_dict = to_dict(project)
        if project.scene_prompts:
            project_dict['scene_prompts'] = json.loads(project.scene_prompts)
        if project.audio_prompts:
            project_dict['audio_prompts'] = json.loads(project.audio_prompts)
        if project.remote_video_urls:
            project_dict['video_urls'] = json.loads(project.remote_video_urls)
        if project.remote_combined_url:
            project_dict['combined_video_url'] = project.remote_combined_url
            
        result.append(project_dict)
    
    return result

@app.get("/api/video-project/{video_project_id}")
async def get_video_project(video_project_id: str, request: Request, db: Session = Depends(get_db)):
    """
    Get details for a specific video project
    """
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = request.state.user
    
    project = db.query(VideoProject).filter(
        VideoProject.video_project_id == video_project_id,
        VideoProject.user_id == user.user_id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    result = to_dict(project)
    
    if project.scene_prompts:
        result['scene_prompts'] = json.loads(project.scene_prompts)
    if project.audio_prompts:
        result['audio_prompts'] = json.loads(project.audio_prompts)
    if project.remote_video_urls:
        result['video_urls'] = json.loads(project.remote_video_urls)
    if project.remote_combined_url:
        result['combined_video_url'] = project.remote_combined_url
        
    try:
        response = requests.get(f"{AI_BACKEND_URL}/session/{video_project_id}")
        if response.status_code == 200:
            backend_data = response.json()
            
            if 'video_urls' in backend_data and backend_data['video_urls']:
                result['video_urls'] = backend_data['video_urls']
            if 'combined_video_url' in backend_data and backend_data['combined_video_url']:
                result['combined_video_url'] = backend_data['combined_video_url']
    except:
        pass
        
    return result

@app.get("/proxy-video/{video_project_id}/{filename}")
async def proxy_video(video_project_id: str, filename: str):
    """Proxy video requests to the AI backend"""
    backend_url = f"{AI_BACKEND_URL}/videos/{filename}"
    
    try:
        response = requests.get(backend_url, stream=True)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Video not found on backend")
        
        from starlette.responses import StreamingResponse
        return StreamingResponse(
            content=response.iter_content(chunk_size=8192),
            media_type=response.headers.get("Content-Type", "video/mp4")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error proxying video: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)