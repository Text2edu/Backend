from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from dotenv import load_dotenv

load_dotenv()

engine = create_engine(os.getenv("DATABASE_URL"))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Debugging: Check database connection
try:
    with engine.connect() as connection:
        print("Database connection established successfully!")
except Exception as e:
    print(f"Database connection failed: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
