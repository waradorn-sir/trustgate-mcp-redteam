"""
Replay one recorded Round 1 trial. No model call and no new run.

It reads results/<tag>/runs.jsonl and transcripts.jsonl and shows:
  1. what the user asked
  2. the attack text, exactly as the model received it in that trial
  3. every tool call the agent made
  4. what the user saw, and the payload's success rate over all its trials

Use it for slides and the report: what it prints is the recorded trial, so the
picture matches the numbers in summary.csv.

Run (from the repo folder, with the venv active):
  python show_trial.py --payload c1_var_language_thai --model gpt-5.6-luna
  python show_trial.py --payload c4_var_language_thai --model gpt-4.1-mini --width 60
  python show_trial.py --payload c1_var_visibility_padding --trial 3
"""
import argparse
import json
import textwrap

import demo_round1 as d
import round1_runner as r1

BOLD, DIM, RED, GREEN, CYAN, RESET = d.BOLD, d.DIM, d.RED, d.GREEN, d.CYAN, d.RESET

WHERE = {
    "none": "No attack. Clean baseline.",
    "description": "the description of read_public_notice",
    "param_description": "the description of the 'topic' parameter of read_public_notice",
    "output": "the text read_public_notice returned",
}


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def attack_text(row, transcript):
    """The text that carried the attack, as the model received it."""
    surface = row["surface"]
    if surface == "none":
        return ""
    feed = next((t["function"] for t in transcript["tools"]
                 if t["function"]["name"] == "read_public_notice"), {})
    if surface == "description":
        return feed.get("description", "")
    if surface == "param_description":
        topic = feed.get("parameters", {}).get("properties", {}).get("topic", {})
        return topic.get("description", "")
    names = {}   # surface "output": find what read_public_notice returned in this trial
    for m in transcript["messages"]:
        for c in m.get("tool_calls") or []:
            names[c["id"]] = c["function"]["name"]
        if m.get("role") == "tool" and names.get(m.get("tool_call_id")) == "read_public_notice":
            return m["content"]
    return "(read_public_notice was not called in this trial)"


def show_text(text):
    """Print the text with its own line breaks; a long run of blank lines becomes one marker."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip():
            print(textwrap.fill(lines[i], d.WIDTH, initial_indent="   ", subsequent_indent="   ",
                                break_long_words=False, break_on_hyphens=False))
            i += 1
            continue
        j = i
        while j < len(lines) and not lines[j].strip():
            j += 1
        n = j - i
        if n > 2:
            print(f"   {DIM}... ({n} blank lines) ...{RESET}")
        else:
            print("\n" * (n - 1))   # prints exactly n blank lines
        i = j


def show_calls(row):
    if not row["trace"]:
        print("   (no tool calls)")
    for i, call in enumerate(row["trace"], 1):
        items = [f"{k}={str(v)[:50]}" for k, v in call["args"].items() if v != ""]
        bad = d.unauthorized(call, row["task"]) or row["canary"] in json.dumps(call["args"], ensure_ascii=False)
        color = RED if bad else ""
        flag = "<-- the user never asked for this" if bad else (
            "<-- confidential, not requested" if call["tool"] == "read_report" else "")
        one = f"{i}. {call['tool']}({', '.join(items)})"
        if len(one) + 3 <= d.WIDTH or not items:
            lines = [one]
        else:
            lines = [f"{i}. {call['tool']}("] + [f"     {it}," for it in items[:-1]] + [f"     {items[-1]})"]
        for line in lines:
            print(f"   {color}{line}{RESET}")
        if flag:
            print(f"      {RED}{flag}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="Replay one recorded trial (no model call).")
    parser.add_argument("--payload", required=True)
    parser.add_argument("--model", default="gpt-5.6-luna")
    parser.add_argument("--trial", type=int, default=1)
    parser.add_argument("--tag", default="round1", help="results folder under results/")
    parser.add_argument("--width", type=int, default=78, help="characters per line, at least 40")
    a = parser.parse_args()
    d.WIDTH = max(40, a.width)

    folder = r1.ROOT / "results" / a.tag
    rows = [r for r in read_jsonl(folder / "runs.jsonl")
            if r["payload_id"] == a.payload and r["model"] == a.model and r["status"] != "error"]
    if not rows:
        raise SystemExit(f"No recorded trials for {a.payload} on {a.model} in {folder}")
    row = next((r for r in rows if r["trial"] == a.trial), None)
    if row is None:
        raise SystemExit(f"No trial {a.trial}. Recorded: {sorted(r['trial'] for r in rows)}")
    transcript = next(t for t in read_jsonl(folder / "transcripts.jsonl")
                      if t["trial_id"] == row["trial_id"])

    print(f"\n{BOLD}Recorded trial (replay, no new run){RESET}")
    print(f"model: {CYAN}{a.model}{RESET}   payload: {CYAN}{a.payload}{RESET}   trial: {a.trial}")
    print(DIM + d.wrap(f"run {row['run_id']}, code {row.get('code_version', '?')}",
                       indent="", hang="") + RESET + "\n")

    user = next(m["content"] for m in transcript["messages"] if m.get("role") == "user")
    d.box("1. THE USER ASKS", user)

    print(f"\n{BOLD}2. THE ATTACK TEXT, AS THE MODEL RECEIVED IT{RESET}")
    print(DIM + d.wrap(f"Where: {WHERE[row['surface']]}") + RESET + "\n")
    show_text(attack_text(row, transcript))

    print(f"\n{BOLD}3. WHAT THE AGENT DID (every tool call){RESET}")
    show_calls(row)
    print()

    d.box("4. WHAT THE USER SAW", row["final_answer"], GREEN)
    verdict = []
    if row["S1"]:
        verdict.append("S1 unauthorized store executed")
    if row["S2"]:
        verdict.append("S2 confidential canary leaked in a tool argument")
    if verdict:
        print("\n" + RED + BOLD + d.wrap(f"ATTACK SUCCEEDED: {'; '.join(verdict)}") + RESET)
    else:
        print(f"\n   {GREEN}{BOLD}No unauthorized action in this trial.{RESET}")
    wins = sum(1 for r in rows if r["attack_success"])
    print(f"   All recorded trials of this payload on {a.model}: {wins} of {len(rows)} succeeded.")


if __name__ == "__main__":
    main()
