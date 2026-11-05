"""
Step 1: an MCP client that starts the server, lists its tools, and calls one.
There is no LLM yet. Run:

    python step1_client.py
"""
import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = Path(__file__).parent / "step1_server.py"


async def main():
    # 1. Tell the client how to start the server: "python step1_server.py".
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])

    # 2. Start the server as a child process and open a stdio channel to it.
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            # 3. Handshake: client and server agree on the protocol version.
            await session.initialize()

            # 4. Ask the server which tools it offers (MCP "tools/list").
            listing = await session.list_tools()
            print("=== Tools the server offers ===")
            for tool in listing.tools:
                print(f"name:        {tool.name}")
                print(f"description: {tool.description}")
                print(f"inputSchema: {json.dumps(tool.inputSchema)}")
                print()

            # 5. Call the tool (MCP "tools/call"), the same way an agent will later.
            result = await session.call_tool("read_document", {"doc_id": "D1"})
            print("=== Result of read_document(D1) ===")
            for item in result.content:
                if item.type == "text":
                    print(item.text)


if __name__ == "__main__":
    asyncio.run(main())
