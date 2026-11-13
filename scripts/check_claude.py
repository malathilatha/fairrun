"""Check that FairRun can reach Claude, and say exactly why not if it can't.

Command Prompt:  set ANTHROPIC_API_KEY=...   then   python scripts\\check_claude.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fairrun.agent import PLANNER_MODEL, REVIEWER_MODEL  # noqa: E402

key = os.environ.get("ANTHROPIC_API_KEY", "")
if not key:
    sys.exit("1. FAIL: ANTHROPIC_API_KEY is not set in this window.")
print(f"1. Key is set (starts {key[:7]}..., length {len(key)})")

try:
    import anthropic
except ImportError:
    sys.exit("2. FAIL: the 'anthropic' package is not installed. Run: pip install anthropic")
print(f"2. anthropic package {anthropic.__version__} installed")

client = anthropic.Anthropic()
for model in (PLANNER_MODEL, REVIEWER_MODEL):
    try:
        msg = client.messages.create(model=model, max_tokens=20,
                                     messages=[{"role": "user", "content": "Reply with the word OK."}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        print(f"3. {model}: OK -> {text.strip()!r}")
    except Exception as e:
        print(f"3. {model}: FAILED -> {type(e).__name__}: {str(e)[:300]}")
        print("   If the model name is the problem, set FAIRRUN_PLANNER_MODEL / FAIRRUN_REVIEWER_MODEL "
              "to a model listed in your Claude Console.")
