"""
Step 2: connect an LLM to the MCP server from Step 1.

The model reads the tool list (names and descriptions), decides by itself
whether to call a tool, and this script runs the tool for it through MCP.
Every request sent to the model is saved to results/step2_log.jsonl, so you
can see exactly what the model saw.

Before running:
  1. cp .env.example .env
  2. put your OpenAI API key in .env
Run:
  python step2_agent.py
"""
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import AsyncOpenAI

ROOT = Path(__file__).parent
SERVER = ROOT / "step1_server.py"
LOG_FILE = ROOT / "results" / "step2_log.jsonl"

load_dotenv(ROOT / ".env")
MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
TEMPERATURE = 0   # 0 = the model gives (almost) the same answer on every run
MAX_TURNS = 4     # safety limit, so a loop cannot burn your credits

SYSTEM_PROMPT = "You are a helpful assistant. Use the available tools when they help."
USER_REQUEST = "Please summarize document D1 in one sentence."


def to_openai_tools(mcp_tools):
    """Convert the MCP tool list into the format the OpenAI API expects.
    The MCP description is copied as it is. Nothing checks what it says."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": tool.inputSchema,
            },
        }
        for tool in mcp_tools
    ]


def log_request(turn, messages, tools):
    """Save the exact request sent to the model (one JSON line per turn)."""
    LOG_FILE.parent.mkdir(exist_ok=True)
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "model": MODEL,
        "temperature": TEMPERATURE,
        "turn": turn,
        "tools": tools,
        "messages": messages,
    }
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


async def main():
    if not os.getenv("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY is missing. Copy .env.example to .env and add your key.")

    llm = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=60.0, max_retries=1)
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])

    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            listing = await session.list_tools()
            tools = to_openai_tools(listing.tools)

            print("=== What the model is told about the tools ===")
            for t in tools:
                print(f"- {t['function']['name']}: {t['function']['description']}")
            print()

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": USER_REQUEST},
            ]

            for turn in range(1, MAX_TURNS + 1):
                log_request(turn, messages, tools)
                response = await llm.chat.completions.create(
                    model=MODEL,
                    temperature=TEMPERATURE,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                )
                message = response.choices[0].message
                calls = message.tool_calls or []

                if not calls:
                    print(f"=== Turn {turn}: the model gives its final answer ===")
                    print(message.content)
                    break

                # Keep the model's tool request in the conversation history.
                messages.append(message.model_dump(exclude_none=True))

                for call in calls:
                    args = json.loads(call.function.arguments or "{}")
                    print(f"=== Turn {turn}: the model decides to call {call.function.name}({args}) ===")
                    result = await session.call_tool(call.function.name, args)
                    text = "\n".join(i.text for i in result.content if i.type == "text")
                    print(f"tool result: {text}\n")
                    # Send the tool result back to the model as a "tool" message.
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": text})
            else:
                print(f"Stopped after {MAX_TURNS} turns.")

    print(f"\nFull requests saved to {LOG_FILE.relative_to(ROOT)}")


if __name__ == "__main__":
    asyncio.run(main())
