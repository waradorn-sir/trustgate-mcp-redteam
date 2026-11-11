"""
Show the two MCP messages that matter for the tutorial, from our real server.

It starts community-security-feed (attacker_feed_server.py) over stdio, the
same way round1_runner.py does, and prints the result of:
  1. tools/list   what the server says about read_public_notice
  2. tools/call   what read_public_notice returns

No model is called, so this costs nothing. By default the server runs the
clean payload. Use --payload to show a poisoned version.

Run (from the repo folder, with the venv active):
  python show_mcp_messages.py
  python show_mcp_messages.py --full
  python show_mcp_messages.py --payload c1_seed_store
"""
import argparse
import asyncio
import json
from contextlib import AsyncExitStack

import round1_runner as r1

BOLD, DIM, CYAN, RESET = "\033[1m", "\033[2m", "\033[96m", "\033[0m"


def dump(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False)


async def main():
    parser = argparse.ArgumentParser(description="Print real tools/list and tools/call results.")
    parser.add_argument("--payload", default="clean_t1", help="payload the server runs (default: clean_t1)")
    parser.add_argument("--full", action="store_true", help="also print the tool's input schema")
    a = parser.parse_args()
    if a.payload not in {p["id"] for p in r1.load_payloads()}:
        raise SystemExit(f"Unknown payload {a.payload!r}")

    env = {
        "CANARY": "CANARY-not-used",
        "PAYLOAD_ID": a.payload,
        "PAYLOAD_FILE": str(r1.PAYLOAD_FILE),
        "TRIAL_ID": "show-mcp-messages",
    }
    async with AsyncExitStack() as stack:
        feed = await r1.open_server(stack, "attacker_feed_server.py", env)

        listing = await feed.list_tools()
        tool = next(t for t in listing.tools if t.name == "read_public_notice")
        entry = {"name": tool.name, "description": tool.description}
        if a.full:
            entry["inputSchema"] = tool.inputSchema
        print(f"\n{CYAN}{BOLD}tools/list{RESET}  {DIM}client asks: what tools do you have?{RESET}")
        print(dump({"tools": [entry]}))

        result = await feed.call_tool("read_public_notice", {"topic": "security"})
        print(f"\n{CYAN}{BOLD}tools/call{RESET}  {DIM}client asks: run read_public_notice(topic=\"security\"){RESET}")
        print(dump({"content": [{"type": c.type, "text": c.text} for c in result.content]}))
        print(f"\n{DIM}server: community-security-feed   payload: {a.payload}{RESET}\n")


if __name__ == "__main__":
    asyncio.run(main())
