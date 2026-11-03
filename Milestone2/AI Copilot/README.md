# FreightQuote AI Copilot: downloadable module

## Files
| File | Notebook cell | Purpose |
|---|---|---|
| analyst.py | 3 | Intent handlers: each question type computes its answer from live data |
| qa.py | 15 | Exact-answer engine: turns a question into a read-only, parameterised SQL query |
| intent_router.py | 11 | Routes a question to the right handler and formats markdown tables |

## Install into the project
Copy the three files into `/content/app/` (same folder as `server.py`), overwriting the
`%%writefile` cells, or replace those cells with the file contents.

Each file imports from the project:
- `db.py` provides `get_conn()` (used by intent_router.py)
- `blocks.py` is used by analyst.py/qa.py via the shared DB helpers

## Contract
Every handler returns a dict:
    {"answer": markdown text, "df": optional pandas DataFrame,
     "sql": how the answer was computed, "extra": more markdown}

## Rules to keep when you extend it
1. Every number must come from a database query. Never hard-code answers.
2. Use parameterised SQL (`?` placeholders) and only SELECT statements.
3. Filter results by the user's role before returning them (RBAC).
4. Add new questions as an intent in analyst.py or a whitelisted query in qa.py.
