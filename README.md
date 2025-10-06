# quote-builder-llm-benchmark
This repository benchmarks Large Language Models (LLMs) on their ability to generate secure and functional backend code. Each model receives the same prompt to implement a minimal authentication API, and the generated code is automatically evaluated using a standardized pytest suite.


# Instructions to run

bash:
pip install -r requirements-tests.txt
python run_benchmark.py


This will:

Run tests/test_auth_api.py once per candidate

Export a tiny conftest sanity JSON (import ok, create_app present)

Export the pytest JSON report per run

Insert one row per candidate into database/benchmark_results.db with:

candidate – file stem (e.g., app_1)

solution – raw code of that candidate

result_conftest – the conftest mini JSON

result_test_auth_api – the full pytest JSON (plus a mini_summary)


# How to read the results

sql:

SELECT candidate,
       json_extract(result_test_auth_api, '$.mini_summary.passed') AS passed,
       json_extract(result_test_auth_api, '$.mini_summary.failed') AS failed,
       created_at
FROM results
ORDER BY id DESC;
