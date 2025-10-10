import os, sys, subprocess, shlex, textwrap

PROVIDER = os.getenv("GEN_PROVIDER", "ollama")   # "ollama" or "openai"
MODEL    = os.getenv("GEN_MODEL",    "qwen2.5-coder:7b")
OUTFILE  = sys.argv[1]  # e.g. candidates/app_1.py
PROMPT   = sys.argv[2]  # e.g. prompt_authapi.txt

if PROVIDER == "ollama":
    cmd = f"""
SYSTEM='You are a senior backend engineer. Output ONLY Python code for a single module. No comments, no explanations, no markdown fences.'
USER_PROMPT_JSON=$(jq -Rs . < {shlex.quote(PROMPT)})

curl -s http://127.0.0.1:11434/api/generate \
  -H "Content-Type: application/json" \
  --data-binary @- <<EOF | sed -E 's/^```[a-zA-Z]*$//; s/^```$//' > {shlex.quote(OUTFILE)}
{{
  "model": "{MODEL}",
  "system": "$SYSTEM",
  "prompt": $USER_PROMPT_JSON,
  "stream": false,
  "options": {{ "temperature": 0.2, "num_ctx": 4096, "num_predict": 2048 }}
}}
EOF
"""
    subprocess.run(cmd, shell=True, check=True, executable="/bin/bash")

elif PROVIDER == "openai":
    subprocess.run(
        ["python", "providers/openai_generate.py", OUTFILE, PROMPT, os.getenv("OPENAI_MODEL", "gpt-4o")],
        check=True
    )
else:
    raise SystemExit(f"Unknown GEN_PROVIDER={PROVIDER} (use 'ollama' or 'openai')")
