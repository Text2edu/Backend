from uuid import uuid4
from sqlalchemy import Column, String, ForeignKey, Table, TIMESTAMP, func, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base
import datetime

Base = declarative_base()

# Association Table: Users <-> Chats (Many-to-Many)
user_chat_table = Table(
    "user_chat",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.user_id"), primary_key=True),
    Column("chat_id", UUID(as_uuid=True), ForeignKey("chats.chat_id"), primary_key=True),
)

# Association Table: Chats <-> Messages (One-to-Many)
chat_msg_table = Table(
    "chat_msg",
    Base.metadata,
    Column("chat_id", UUID(as_uuid=True), ForeignKey("chats.chat_id"), primary_key=True),
    Column("msg_id", UUID(as_uuid=True), ForeignKey("messages.msg_id"), primary_key=True),
)

class User(Base):
    __tablename__ = "users"

    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)  # Store hashed password
    email = Column(String, nullable=False, unique=True)
    access_level = Column(String, default="general")

class Chat(Base):
    __tablename__ = "chats"

    chat_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    title = Column(String, nullable=False)
    created_on = Column(TIMESTAMP(timezone=True), default=func.now())

class Msg(Base):
    __tablename__ = "msgs"

    msg_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    text_content = Column(String, nullable=True)
    media_content = Column(String, nullable=True)
    sender = Column(String, nullable=True)

class VideoProject(Base):
    __tablename__ = "video_projects"

    video_project_id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=False)
    topic = Column(String, nullable=False)
    status = Column(String, nullable=False, default="initializing")
    scene_prompts = Column(Text)  
    audio_prompts = Column(Text)  
    remote_video_urls = Column(Text)  # 
    remote_combined_url = Column(String)  
    error_message = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

