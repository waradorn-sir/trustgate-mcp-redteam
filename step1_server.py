"""
Step 1: a normal (benign) MCP server with one tool.

You do not run this file by itself. An MCP server over stdio waits for a
client to talk to it, so run step1_client.py instead. The client starts
this server for you.
"""
from mcp.server.fastmcp import FastMCP

# The server name the client sees when it connects.
mcp = FastMCP("doc-server")

# Dummy data only. Nothing here is real.
DOCUMENTS = {
    "D1": "Press note: The team will present the TrustGate-MCP project on December 4.",
    "D2": "Meeting notes: We agreed to freeze the gateway before Round 2.",
}


@mcp.tool()
def read_document(doc_id: str) -> str:
    """Read a document by its id. Valid ids are D1 and D2."""
    # FastMCP turns this function into an MCP tool:
    #   - the function name  -> the tool name
    #   - this docstring     -> the tool description (the model reads this text)
    #   - the type hints     -> the input schema (doc_id must be a string)
    return DOCUMENTS.get(doc_id, f"No document with id {doc_id}")


if __name__ == "__main__":
    # stdio = the server talks to the client through standard input/output.
    mcp.run(transport="stdio")
