# Quote-Builder LLM Benchmark

This repository benchmarks Large Language Models (LLMs) on their ability to generate secure and functional backend code.
Each model receives the same coding task — to implement a minimal authentication API in Flask — and the generated solutions are automatically tested using a standardized pytest suite.

# Benchmark Overview

## Goal:
Evaluate how well different LLMs generate secure, correct, and efficient Python code for backend tasks.

Each run performs:

✅ Automatic generation of code from a consistent prompt (prompt_authapi.txt)

✅ Security & correctness testing with pytest

✅ Result logging in a SQLite database for easy comparison

# How to Run the Benchmark

## 1. Install dependencies
pip install -r requirements-tests.txt

## 2. Run the benchmark
python run_benchmark.py


# This will:

Execute tests/test_auth_api.py once for every candidate file in /candidates

Generate a mini JSON sanity check (conftest)

Export full pytest results per model (report.json)

Save all results in database/benchmark_results.db

# Adding New Models

You can easily benchmark a new model by generating its code via API and saving it as a new file under /candidates/.

## Example (using Qwen 3 Coder Plus)
curl -s -X POST https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions \
  -H "Authorization: Bearer $DASHSCOPE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen-coder-plus",
    "messages": [
      {"role": "system", "content": "You are a senior backend engineer. Output ONLY Python code for a single module."},
      {"role": "user", "content": "'"$(cat prompt_authapi.txt)"'"}
    ]
  }' \
| jq -r '.choices[0].message.content' > candidates/app_qwen.py


Repeat similarly for other APIs (Claude, Gemini, GPT-5, etc.).
Each new file (e.g., app_claude.py, app_gemini.py) will be automatically included in the next benchmark run.

# For Viewing Results

Make sure to install the extension SQLite Viewer.