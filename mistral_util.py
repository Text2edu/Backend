from mistralai.client import MistralClient
import os
from dotenv import load_dotenv

load_dotenv()

def formatMsg(msg, role = "user"):
  return {"role": role, "content": msg}

def generateTitle(prompt):
  msgs.append(formatMsg(f'Message: "{prompt}"\nText: '))
  resp = mistral_client.chat(model=model, messages=msgs)
  
  msgs.pop()

  return resp.choices[0].message.content

def getDirection(prompt,user_id,chat_id):
   hist_file = open(f'history/{user_id}_{chat_id}','a+')
   history = hist_file.read()

   msgs_temp.append(formatMsg(role='system',msg=f'''Here is a history of your conversation with the user for reference only don't defer from final format:-
                              {history}'''))
   
   resp = mistral_client.chat(model=model, messages=msgs_temp)
   ans = resp.choices[0].message.content
   ans = ans[ans.find('You:')+7:]

   hist_file.write(f'USER: {prompt}\n')
   hist_file.write(f'AI: {ans}\n')

   return ans

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
formatMsg(role='system',msg='## GENERATE ONLY A SINGLE TITLE')
]

msgs_temp= [
  formatMsg(role='system', msg='''You are a cinematic director in a text-to-video application. Your job is to take a user's creative prompt and convert it into a sequence of clear, coherent scenes.

Each scene should:
- Be a standalone, descriptive visual moment (suitable for 5–10 seconds of video).
- Be consistent in tone, setting, and characters unless transition is intentional.
- Include a short **scene title**, a **description of what happens visually**, **camera movement or shot style** if needed, and **emotional tone**.
- Use vivid visual language, not internal thoughts.

Final output format:
Scene 1:
Title: [Title]
Description: [Visual events in the scene]
Camera Direction: [Optional, e.g., "Close-up", "Wide aerial shot", "Slow pan"]
Tone: [Mood, e.g., "Melancholic", "Hopeful", "Tense"]

Repeat this format for each scene.
Limit the total number of scenes to 5-7 depending on the complexity of the user's prompt.
Ensure scenes flow logically to create a cohesive mini-story.
'''),
]
