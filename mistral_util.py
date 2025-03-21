from mistralai.client import MistralClient
import os
from dotenv import load_dotenv

load_dotenv()

def formatMsg(msg, role = "user"):
  return {"role": role, "content": msg}

mistral_client = MistralClient(api_key=os.getenv('MISTRAL_API_KEY'))
model = "mistral-small"

msgs = [
    formatMsg(role="system",msg='''You're an AI assistant that generates chat titles. Given a user's message, return a relevant and concise title (max 5 words).

Examples:
Message: "Explain how to use Riverpod with Flutter."
Title: "Riverpod in Flutter"

Message: "What's the best way to cache images?"
Title: "Image Caching Techniques"

Message: "How do I center a widget?"
Title: "Centering Widgets in Flutter"'''),
]
