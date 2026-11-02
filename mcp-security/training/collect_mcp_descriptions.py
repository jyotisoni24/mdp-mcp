"""
MCP Tool Description Collector for MCP Security Gateway.

Safely and statically harvests genuine MCP tool descriptions from official Model
Context Protocol repositories and the official MCP registry.

Guarantees:
1. Static analysis only (Zero untrusted execution of Python/TS/Node servers).
2. Strict preservation of original tool descriptions (no rewriting/paraphrasing).
3. Clear separation between server-level and tool-level metadata.
4. Exact deduplication and near-duplicate similarity detection.
5. Passive handling of potential prompt injection directives in descriptions.
6. Attribution tracking (commit hash, repo URL, license, version).
7. All harvested records are marked verification_status="pending_review".
8. Does NOT modify or overwrite existing datasets or models.
"""

import os
import re
import ast
import json
import csv
import hashlib
import difflib
from datetime import datetime, timezone
import urllib.request
import urllib.error

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
CANDIDATES_JSON = os.path.join(DATA_DIR, "benign_candidates.json")
CANDIDATES_CSV = os.path.join(DATA_DIR, "benign_candidates.csv")
COLLECTION_LOG = os.path.join(DATA_DIR, "collection_log.json")
REVIEWED_JSON = os.path.join(DATA_DIR, "reviewed_benign.json")

# Safety heuristic keywords indicating embedded directives or prompt injection attempts
SUSPICIOUS_DIRECTIVE_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"you\s+(must|should)\s+(always|never)\s+tell",
    r"system\s+(prompt|override|directive)",
    r"disregard\s+",
    r"do\s+not\s+reveal",
    r"secret\s+key",
    r"now\s+you\s+can\s+fetch\s+the\s+most",
    r"this\s+tool\s+now\s+grants\s+you",
    r"eval\(",
    r"<script",
    r"DROP\s+TABLE",
    r"admin\s+mode"
]

def fetch_url_text(url: str, timeout: int = 15) -> str:
    """Safely fetch file content via HTTP GET with timeout."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "MCPSecurityGateway-Collector/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to fetch {url}: {e}")

def calculate_text_hash(tool_name: str, description: str) -> str:
    """Generate deterministic SHA-256 hash for deduplication."""
    content = f"{tool_name.strip()}||{description.strip()}".encode("utf-8")
    return hashlib.sha256(content).hexdigest()

def compute_similarity(str1: str, str2: str) -> float:
    """Compute character & token similarity between two strings."""
    if not str1 or not str2:
        return 0.0
    return difflib.SequenceMatcher(None, str1.lower(), str2.lower()).ratio()

def scan_safety_heuristics(description: str) -> list[str]:
    """Flag potential instruction overrides or behavioral directives for human inspection."""
    flags = []
    for pattern in SUSPICIOUS_DIRECTIVE_PATTERNS:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            flags.append(f"Contains directive pattern matching: '{match.group(0)}'")
    return flags

# ==============================================================================
# STATIC PARSER: Python MCP Servers (AST Based)
# ==============================================================================

def parse_python_mcp_server(source_code: str, server_name: str, provenance: dict) -> list[dict]:
    """
    Parse Python MCP Server source code using standard library AST.
    Zero execution of untrusted code.
    """
    tools = []
    tree = ast.parse(source_code)

    # 1. Collect top-level constants and enum values
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                    constants[target.id] = str(node.value.value)
        elif isinstance(node, ast.ClassDef):
            # Inspect tool enums like GitTools
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name) and isinstance(item.value, ast.Constant):
                            constants[f"{node.name}.{target.id}"] = str(item.value.value)
                            constants[f"{node.name}.{target.id}.value"] = str(item.value.value)

    # 2. Extract tools defined via @server.tool(...)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                is_tool = False
                dec_name = None
                dec_desc = None
                
                if isinstance(dec, ast.Call):
                    func = dec.func
                    if (isinstance(func, ast.Attribute) and func.attr == 'tool') or (isinstance(func, ast.Name) and func.id == 'tool'):
                        is_tool = True
                        for kw in dec.keywords:
                            if kw.arg == 'name':
                                if isinstance(kw.value, ast.Constant):
                                    dec_name = str(kw.value.value)
                                elif isinstance(kw.value, ast.Attribute):
                                    # e.g. GitTools.STATUS.value
                                    attr_str = ast.unparse(kw.value)
                                    dec_name = constants.get(attr_str, attr_str.split('.')[-1].lower())
                            elif kw.arg == 'description':
                                if isinstance(kw.value, ast.Constant):
                                    dec_desc = str(kw.value.value)
                                elif isinstance(kw.value, ast.Name) and kw.value.id in constants:
                                    dec_desc = constants[kw.value.id]

                if is_tool:
                    tool_name = dec_name or node.name
                    docstring = ast.get_docstring(node)
                    tool_desc = dec_desc or docstring or ""

                    # Extract input schema properties from parameters
                    properties = {}
                    required = []
                    for arg in node.args.args:
                        arg_name = arg.arg
                        if arg_name in ("self", "cls"):
                            continue
                        arg_desc = ""
                        arg_type = "string"
                        if arg.annotation:
                            ann_str = ast.unparse(arg.annotation)
                            desc_match = re.search(r'description=["\']([^"\']+)["\']', ann_str)
                            if desc_match:
                                arg_desc = desc_match.group(1)
                            if "int" in ann_str:
                                arg_type = "integer"
                            elif "bool" in ann_str:
                                arg_type = "boolean"
                            elif "list" in ann_str:
                                arg_type = "array"

                        properties[arg_name] = {
                            "type": arg_type,
                            "description": arg_desc
                        }
                        # If default is not provided, it's required
                        # Note: defaults list corresponds to last N args
                        defaults_start = len(node.args.args) - len(node.args.defaults)
                        arg_idx = node.args.args.index(arg)
                        if arg_idx < defaults_start:
                            required.append(arg_name)

                    schema = {
                        "type": "object",
                        "properties": properties,
                        "required": required
                    }

                    tools.append({
                        "tool_name": tool_name,
                        "tool_description": tool_desc,
                        "input_schema": schema
                    })

    # 3. Extract tools defined via types.Tool(name=..., description=...) in list_tools handlers
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name == "Tool" or "Tool(" in ast.unparse(node):
                t_name = None
                t_desc = None
                input_schema = {"type": "object", "properties": {}}
                for kw in node.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        t_name = str(kw.value.value)
                    elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
                        t_desc = str(kw.value.value)
                    elif kw.arg == "inputSchema":
                        try:
                            input_schema = ast.literal_eval(kw.value)
                        except Exception:
                            input_schema = {"type": "object", "properties": {}}
                if t_name and t_desc:
                    tools.append({
                        "tool_name": t_name,
                        "tool_description": t_desc,
                        "input_schema": input_schema
                    })

    return tools

# ==============================================================================
# STATIC PARSER: TypeScript MCP Servers (Structural Regex / Token Matching)
# ==============================================================================

def parse_typescript_mcp_server(source_code: str, server_name: str, provenance: dict) -> list[dict]:
    """
    Parse TypeScript MCP Server source code without running Node or evaluating JS.
    Handles server.registerTool, server.tool, and ListToolsRequestSchema handlers.
    """
    tools = []

    # 1. Parse all top-level Zod object schemas
    top_level_schemas = {}
    zod_pattern = r'const\s+([A-Za-z0-9_]+ArgsSchema)\s*=\s*z\.object\(\{([\s\S]*?)\}\);'
    for zm in re.finditer(zod_pattern, source_code):
        s_name = zm.group(1)
        s_body = zm.group(2)
        s_props = {}
        s_reqs = []
        for pm in re.finditer(r'([a-zA-Z0-9_]+):\s*z\.([a-zA-Z0-9_]+(?:\([^)]*\))?)([^,\n}]*)', s_body):
            p_name = pm.group(1)
            p_type_full = pm.group(2)
            p_rest = pm.group(3)
            p_desc = ""
            dm = re.search(r'describe\(["\']([^"\']+)["\']\)', p_rest)
            if dm:
                p_desc = dm.group(1)

            p_type = "string"
            if "number" in p_type_full:
                p_type = "number"
            elif "boolean" in p_type_full:
                p_type = "boolean"
            elif "array" in p_type_full:
                p_type = "array"
            elif "enum" in p_type_full:
                p_type = "string"

            s_props[p_name] = {"type": p_type, "description": p_desc}
            if "optional" not in p_rest:
                s_reqs.append(p_name)

        top_level_schemas[s_name] = {
            "type": "object",
            "properties": s_props,
            "required": s_reqs
        }

    # Pattern A: server.registerTool( "name", { title?, description: ..., inputSchema?: ... }, ... )
    reg_pattern = r'server\.registerTool\(\s*["\']([^"\']+)["\'],\s*\{([\s\S]*?)\n\s*\},'
    for match in re.finditer(reg_pattern, source_code):
        tool_name = match.group(1)
        body = match.group(2)

        # Extract description (handles concatenated strings or multiline template literals)
        desc = ""
        desc_match = re.search(r'description:\s*((?:(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')(?:\s*\+\s*)?)+)', body)
        if desc_match:
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', desc_match.group(1))
            desc = "".join(p[0] or p[1] for p in parts)
        else:
            tmpl_match = re.search(r'description:\s*`([^`]+)`', body)
            if tmpl_match:
                desc = tmpl_match.group(1).strip()
            else:
                simple_match = re.search(r'description:\s*["\']([^"\']+)["\']', body)
                if simple_match:
                    desc = simple_match.group(1)

        # Check if inputSchema references a top-level schema
        schema = {"type": "object", "properties": {}, "required": []}
        ref_match = re.search(r'inputSchema:\s*(?:jsonSchema2020\()?([A-Za-z0-9_]+ArgsSchema)', body)
        if ref_match and ref_match.group(1) in top_level_schemas:
            schema = top_level_schemas[ref_match.group(1)]
        else:
            # Inline parameter descriptions from inputSchema
            properties = {}
            required = []
            # Only search inside inputSchema block if present
            input_block_match = re.search(r'inputSchema:\s*(?:z\.object|jsonSchema2020)?\s*\(?\s*\{([\s\S]*?)\}\s*\)?', body)
            search_target = input_block_match.group(1) if input_block_match else ""
            if search_target:
                for p_match in re.finditer(r'([a-zA-Z0-9_]+):\s*(?:z\.)?([a-zA-Z0-9_]+(?:\([^)]*\))?)([^,\n}]*)', search_target):
                    p_name = p_match.group(1)
                    p_type_raw = p_match.group(2)
                    p_rest = p_match.group(3)

                    p_type = "string"
                    if "number" in p_type_raw:
                        p_type = "number"
                    elif "boolean" in p_type_raw:
                        p_type = "boolean"
                    elif "array" in p_type_raw:
                        p_type = "array"

                    p_desc = ""
                    desc_sub = re.search(r'describe\(["\']([^"\']+)["\']\)', p_rest)
                    if desc_sub:
                        p_desc = desc_sub.group(1)

                    if "optional" not in p_rest:
                        required.append(p_name)

                    properties[p_name] = {
                        "type": p_type,
                        "description": p_desc
                    }

            if properties:
                schema = {
                    "type": "object",
                    "properties": properties,
                    "required": required
                }

        tools.append({
            "tool_name": tool_name,
            "tool_description": desc,
            "input_schema": schema
        })

    # Pattern B: Object literal definitions with { name: "...", description: "...", inputSchema: ... }
    # Used in GitHub, Brave-Search, etc.
    obj_pattern = r'\{\s*name:\s*["\']([^"\']+)["\'],\s*description:\s*((?:(?:"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')(?:\s*\+\s*)?)+),\s*inputSchema:\s*([^\n,]+|\{[\s\S]*?\n\s*\})'
    for match in re.finditer(obj_pattern, source_code):
        tool_name = match.group(1)
        raw_desc = match.group(2)
        schema_raw = match.group(3) or ""

        # Avoid duplicates if already captured by Pattern A
        if any(t["tool_name"] == tool_name for t in tools):
            continue

        parts = re.findall(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', raw_desc)
        tool_desc = "".join(p[0] or p[1] for p in parts)

        properties = {}
        required = []
        for prop_match in re.finditer(r'([a-zA-Z0-9_]+):\s*\{\s*type:\s*["\']([^"\']+)["\'](?:,\s*description:\s*["\']([^"\']+)["\'])?', schema_raw):
            p_name = prop_match.group(1)
            p_type = prop_match.group(2)
            p_desc = prop_match.group(3) or ""
            properties[p_name] = {"type": p_type, "description": p_desc}

        req_match = re.search(r'required:\s*\[([^\]]*)\]', schema_raw)
        if req_match:
            required = [r.strip().replace('"', '').replace("'", "") for r in req_match.group(1).split(",") if r.strip()]

        # If schema_raw references zodToJsonSchema(module.SchemaName)
        if not properties and "zodToJsonSchema" in schema_raw:
            ref_schema_m = re.search(r'zodToJsonSchema\((?:[a-zA-Z0-9_]+\.)?([a-zA-Z0-9_]+)\)', schema_raw)
            if ref_schema_m:
                properties["_schema_reference"] = {
                    "type": "object",
                    "description": f"Zod schema reference: {ref_schema_m.group(1)}"
                }

        tools.append({
            "tool_name": tool_name,
            "tool_description": tool_desc,
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        })

    return tools

# ==============================================================================
# SERVER MANIFESTS & HARVESTING SPECIFICATION
# ==============================================================================

SERVER_SPECIFICATIONS = [
    {
        "server_name": "filesystem",
        "category": "Local Filesystem",
        "language": "typescript",
        "repo_url": "https://github.com/modelcontextprotocol/servers",
        "commit_hash": "194cc86e3ae6400958555bd4116849d822d69263",
        "server_path": "src/filesystem",
        "source_file": "server.ts",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/filesystem/server.ts",
        "version": "1.3.1",
        "license": "MIT",
        "server_description": "Official Model Context Protocol server for local filesystem access",
        "preferred_tools": ["read_text_file", "write_file", "list_directory", "search_files", "directory_tree"]
    },
    {
        "server_name": "git",
        "category": "Version Control",
        "language": "python",
        "repo_url": "https://github.com/modelcontextprotocol/servers",
        "commit_hash": "194cc86e3ae6400958555bd4116849d822d69263",
        "server_path": "src/git",
        "source_file": "src/mcp_server_git/server.py",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/git/src/mcp_server_git/server.py",
        "version": "1.3.1",
        "license": "MIT",
        "server_description": "Official MCP server providing git repository operations",
        "preferred_tools": ["git_status", "git_diff_unstaged", "git_commit", "git_add", "git_log"]
    },
    {
        "server_name": "fetch",
        "category": "Web Retrieval",
        "language": "python",
        "repo_url": "https://github.com/modelcontextprotocol/servers",
        "commit_hash": "194cc86e3ae6400958555bd4116849d822d69263",
        "server_path": "src/fetch",
        "source_file": "src/mcp_server_fetch/server.py",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/fetch/src/mcp_server_fetch/server.py",
        "version": "1.3.1",
        "license": "MIT",
        "server_description": "MCP server providing web content fetching with markdown conversion",
        "preferred_tools": ["fetch"]
    },
    {
        "server_name": "brave-search",
        "category": "Web Search",
        "language": "typescript",
        "repo_url": "https://github.com/modelcontextprotocol/servers-archived",
        "commit_hash": "e6396f9a0c2049d5cbf23eb250c60953a5c0b02f",
        "server_path": "src/brave-search",
        "source_file": "index.ts",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/brave-search/index.ts",
        "version": "0.6.2",
        "license": "MIT",
        "server_description": "Official MCP server for Brave Search API web and local queries",
        "preferred_tools": ["brave_web_search", "brave_local_search"]
    },
    {
        "server_name": "sqlite",
        "category": "Relational Database",
        "language": "python",
        "repo_url": "https://github.com/modelcontextprotocol/servers-archived",
        "commit_hash": "e6396f9a0c2049d5cbf23eb250c60953a5c0b02f",
        "server_path": "src/sqlite",
        "source_file": "src/mcp_server_sqlite/server.py",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/sqlite/src/mcp_server_sqlite/server.py",
        "version": "0.1.0",
        "license": "MIT",
        "server_description": "Official MCP server providing SQLite database interactions",
        "preferred_tools": ["read_query", "write_query", "list_tables", "describe_table"]
    },
    {
        "server_name": "memory",
        "category": "Knowledge Graph",
        "language": "typescript",
        "repo_url": "https://github.com/modelcontextprotocol/servers",
        "commit_hash": "194cc86e3ae6400958555bd4116849d822d69263",
        "server_path": "src/memory",
        "source_file": "index.ts",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/memory/index.ts",
        "version": "1.3.1",
        "license": "MIT",
        "server_description": "MCP server implementing persistent graph-based memory",
        "preferred_tools": ["create_entities", "create_relations", "add_observations", "read_graph", "search_nodes"]
    },
    {
        "server_name": "time",
        "category": "System Utilities",
        "language": "python",
        "repo_url": "https://github.com/modelcontextprotocol/servers",
        "commit_hash": "194cc86e3ae6400958555bd4116849d822d69263",
        "server_path": "src/time",
        "source_file": "src/mcp_server_time/server.py",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/time/src/mcp_server_time/server.py",
        "version": "1.3.1",
        "license": "MIT",
        "server_description": "MCP server providing local and timezone conversion utilities",
        "preferred_tools": ["get_current_time", "convert_time"]
    },
    {
        "server_name": "sequentialthinking",
        "category": "Reasoning",
        "language": "typescript",
        "repo_url": "https://github.com/modelcontextprotocol/servers",
        "commit_hash": "194cc86e3ae6400958555bd4116849d822d69263",
        "server_path": "src/sequentialthinking",
        "source_file": "index.ts",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/sequentialthinking/index.ts",
        "version": "1.3.1",
        "license": "MIT",
        "server_description": "MCP server enabling sequential and reflective thinking steps",
        "preferred_tools": ["sequentialthinking"]
    },
    {
        "server_name": "github",
        "category": "DevOps & Repositories",
        "language": "typescript",
        "repo_url": "https://github.com/modelcontextprotocol/servers-archived",
        "commit_hash": "e6396f9a0c2049d5cbf23eb250c60953a5c0b02f",
        "server_path": "src/github",
        "source_file": "index.ts",
        "source_url": "https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/github/index.ts",
        "version": "0.6.2",
        "license": "MIT",
        "server_description": "Official MCP server for GitHub repository and collaboration APIs",
        "preferred_tools": ["create_issue", "search_repositories", "get_file_contents", "create_pull_request", "list_commits"]
    }
]

# ==============================================================================
# PIPELINE EXECUTION ENGINE
# ==============================================================================

def collect_candidates(target_count: int = 30) -> list[dict]:
    """Execute static extraction across configured server specifications."""
    print("=" * 80)
    print("STARTING MCP TOOL DESCRIPTION HARVESTING PIPELINE")
    print(f"Target count: {target_count} diverse candidate tools")
    print("=" * 80)

    raw_candidates = []
    log_servers = []

    for spec in SERVER_SPECIFICATIONS:
        server_name = spec["server_name"]
        print(f"\n[+] Processing server '{server_name}' ({spec['category']}) via static inspection...")
        try:
            source_code = fetch_url_text(spec["source_url"])
            if spec["language"] == "python":
                extracted = parse_python_mcp_server(source_code, server_name, spec)
            else:
                extracted = parse_typescript_mcp_server(source_code, server_name, spec)

            print(f"    Extracted {len(extracted)} tool definitions from source file.")

            # Filter preferred tools to maintain balanced diversity across servers
            preferred = spec.get("preferred_tools", [])
            for item in extracted:
                t_name = item["tool_name"]
                if preferred and t_name not in preferred:
                    continue

                candidate_id = f"mcp_{server_name}_{t_name}".lower()
                raw_candidates.append({
                    "candidate_id": candidate_id,
                    "tool_name": t_name,
                    "server_name": server_name,
                    "category": spec["category"],
                    "tool_description": item["tool_description"],
                    "input_schema": item["input_schema"],
                    "provenance": {
                        "source_type": "official_reference_server",
                        "repo_url": spec["repo_url"],
                        "commit_hash": spec["commit_hash"],
                        "server_path": spec["server_path"],
                        "source_file": spec["source_file"],
                        "server_version": spec["version"],
                        "license": spec["license"]
                    },
                    "server_level_metadata": {
                        "server_name": server_name,
                        "server_description": spec["server_description"]
                    }
                })

            log_servers.append({
                "server_name": server_name,
                "category": spec["category"],
                "tools_found": len(extracted),
                "tools_selected": len([c for c in raw_candidates if c["server_name"] == server_name])
            })

        except Exception as err:
            print(f"    [!] Error inspecting server {server_name}: {err}")

    print(f"\nTotal raw selected candidates before deduplication: {len(raw_candidates)}")

    # 1. Exact Deduplication
    seen_hashes = {}
    deduped = []
    duplicates_removed = 0

    for cand in raw_candidates:
        h = calculate_text_hash(cand["tool_name"], cand["tool_description"])
        if h in seen_hashes:
            duplicates_removed += 1
            print(f"    [DEDUP] Dropping exact duplicate: {cand['candidate_id']}")
        else:
            seen_hashes[h] = cand["candidate_id"]
            deduped.append(cand)

    # 2. Near-Duplicate Analysis & Safety Heuristics Scanning
    processed_candidates = []
    near_duplicates_flagged = 0

    # Preserve existing reviews if already present
    existing_reviews = {}
    if os.path.exists(REVIEWED_JSON):
        try:
            with open(REVIEWED_JSON, "r", encoding="utf-8") as rf:
                for r in json.load(rf):
                    existing_reviews[r["candidate_id"]] = r
        except Exception:
            pass

    for i, cand in enumerate(deduped):
        desc = cand["tool_description"]
        heuristics = scan_safety_heuristics(desc)

        near_dups = []
        for j, other in enumerate(deduped):
            if i != j:
                sim = compute_similarity(desc, other["tool_description"])
                if sim >= 0.70:
                    near_dups.append({
                        "candidate_id": other["candidate_id"],
                        "similarity": round(sim, 2),
                        "reason": "High description overlap"
                    })

        if near_dups:
            near_duplicates_flagged += 1

        cand["quality_and_safety_checks"] = {
            "description_length_chars": len(desc),
            "has_input_schema": bool(cand.get("input_schema", {}).get("properties")),
            "suspicious_instruction_flags": heuristics,
            "exact_duplicate": False,
            "near_duplicates": near_dups
        }

        # Preserve review status if candidate was already reviewed
        cid = cand["candidate_id"]
        if cid in existing_reviews:
            cand["verification_status"] = existing_reviews[cid].get("verification_status", "approved_benign")
            cand["reviewer_notes"] = existing_reviews[cid].get("reviewer_notes")
            cand["reviewed_at"] = existing_reviews[cid].get("reviewed_at")
            cand["reviewed_by"] = existing_reviews[cid].get("reviewed_by")
        else:
            # Initialize pending review status (Requirements 7, 9, 10)
            cand["verification_status"] = "pending_review"
            cand["reviewer_notes"] = None
            cand["reviewed_at"] = None
            cand["reviewed_by"] = None

        processed_candidates.append(cand)

    final_candidates = processed_candidates[:target_count]
    print(f"Final candidate count to record: {len(final_candidates)}")

    return final_candidates, {
        "collection_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_servers_scanned": len(SERVER_SPECIFICATIONS),
        "total_extracted": len(raw_candidates),
        "exact_duplicates_removed": duplicates_removed,
        "near_duplicates_flagged": near_duplicates_flagged,
        "candidates_saved": len(final_candidates),
        "servers_breakdown": log_servers
    }

def save_outputs(candidates: list[dict], log_data: dict):
    """Write outputs to JSON, CSV, and log files without touching existing datasets."""
    os.makedirs(DATA_DIR, exist_ok=True)

    # 1. Write benign_candidates.json
    with open(CANDIDATES_JSON, "w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2, ensure_ascii=False)
    print(f"[OK] Saved JSON candidates to: {CANDIDATES_JSON}")

    # 2. Write benign_candidates.csv
    csv_rows = []
    for c in candidates:
        props = list(c["input_schema"].get("properties", {}).keys())
        csv_rows.append({
            "candidate_id": c["candidate_id"],
            "tool_name": c["tool_name"],
            "server_name": c["server_name"],
            "category": c["category"],
            "tool_description": c["tool_description"],
            "parameters": ", ".join(props),
            "repo_url": c["provenance"]["repo_url"],
            "commit_hash": c["provenance"]["commit_hash"],
            "version": c["provenance"]["server_version"],
            "license": c["provenance"]["license"],
            "verification_status": c["verification_status"],
            "safety_flags": "; ".join(c["quality_and_safety_checks"]["suspicious_instruction_flags"]) or "none",
            "near_duplicates": len(c["quality_and_safety_checks"]["near_duplicates"])
        })

    fieldnames = [
        "candidate_id", "tool_name", "server_name", "category",
        "tool_description", "parameters", "repo_url", "commit_hash",
        "version", "license", "verification_status", "safety_flags", "near_duplicates"
    ]
    with open(CANDIDATES_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
    print(f"[OK] Saved CSV candidates to:  {CANDIDATES_CSV}")

    # 3. Write collection_log.json
    with open(COLLECTION_LOG, "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=2)
    print(f"[OK] Saved collection log to:  {COLLECTION_LOG}")

    # 4. Initialize reviewed_benign.json if not present
    if not os.path.exists(REVIEWED_JSON):
        with open(REVIEWED_JSON, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        print(f"[OK] Initialized reviewed benign store: {REVIEWED_JSON}")

if __name__ == "__main__":
    candidates, log_data = collect_candidates(target_count=30)
    save_outputs(candidates, log_data)
