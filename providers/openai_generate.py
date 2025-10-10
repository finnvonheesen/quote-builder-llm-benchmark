import os, sys
from openai import OpenAI

def main(out_path: str, prompt_path: str, model: str):
    system = "You are a senior backend engineer. Output ONLY Python code for a single module. No comments, no explanations, no markdown fences."
    with open(prompt_path, "r", encoding="utf-8") as f:
        user = f.read()

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    r = client.chat.completions.create(
        model=model,                # e.g., "gpt-4o"
        temperature=0.0,
        messages=[
            {"role":"system", "content": system},
            {"role":"user",   "content": user},
        ],
    )
    content = (r.choices[0].message.content or "")
    # strip code fences if present
    content = content.replace("```python", "").replace("```", "")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote {out_path}")

if __name__ == "__main__":
    # usage: python providers/openai_generate.py candidates/app_openai.py prompt_authapi.txt gpt-4o
    out = sys.argv[1]
    prompt = sys.argv[2]
    model = sys.argv[3] if len(sys.argv) > 3 else os.getenv("OPENAI_MODEL", "gpt-4o")
    main(out, prompt, model)
