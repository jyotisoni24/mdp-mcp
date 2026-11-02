"""Generate a diverse, realistic dataset of safe MCP tool descriptions.

This script creates legitimate tool descriptions covering standard MCP categories:
- Filesystem operations (reading, writing, listing directories)
- Math, calculations, and billing
- Git & GitHub tools (issues, PRs, commits)
- SQLite & database queries
- Web scraping, HTTP requests, and search
- Time & system utilities
- Security & data validation (checksums, schema validation)
- Harmless updates, rewrites, and edge cases

Each example is labeled safe (0), with attack_type='None'.
"""
from __future__ import annotations

import json
from pathlib import Path


def generate_safe_dataset() -> list[dict]:
    safe_tools: list[dict] = []

    categories = {
        "filesystem": [
            ("read_file", "Read the complete contents of a file at the specified path as UTF-8 encoded text. Returns file content.", "FileSystem"),
            ("read_lines", "Read lines from a file within a given range (start_line to end_line). Helpful for inspecting large source files.", "FileSystem"),
            ("write_file", "Write provided text content to a destination path. Creates parent folders if missing. Overwrites if specified.", "FileSystem"),
            ("append_file", "Append a string to the end of an existing file. Fails if the file does not exist.", "FileSystem"),
            ("list_directory", "List all entries inside a directory, returning filenames, directory flags, and modification timestamps.", "FileSystem"),
            ("directory_tree", "Recursively scan a directory up to a maximum depth and return a nested directory hierarchy representation.", "FileSystem"),
            ("get_file_metadata", "Retrieve metadata for a specified path, including byte size, file permissions, creation date, and last modified date.", "FileSystem"),
            ("delete_file", "Safely delete a single file at the specified path after checking for write permissions.", "FileSystem"),
            ("move_file", "Move or rename a file or directory from source path to destination path within the allowed workspace root.", "FileSystem"),
            ("copy_file", "Copy a file from source location to target location, preserving source file permissions.", "FileSystem"),
            ("find_files", "Search directory recursively for files matching a filename glob pattern (e.g. *.py or *.json).", "FileSystem"),
        ],
        "math_and_logic": [
            ("simple_division", "Perform ordinary arithmetic division of number a by number b. Returns a / b. Raises ZeroDivisionError if b is zero.", "Calculator"),
            ("calculate_sum", "Calculate the arithmetic sum of a list of numeric values. Returns a float or integer sum.", "Calculator"),
            ("calculate_total", "Calculate the total price for an order: sums item prices, applies percentage discount, and adds regional sales tax.", "Billing"),
            ("multiply_numbers", "Multiply two numbers a and b and return the product.", "Calculator"),
            ("calculate_mean", "Compute the arithmetic mean of a list of numbers.", "Statistics"),
            ("calculate_median", "Compute the median value of a numerical series, sorting values and finding middle item.", "Statistics"),
            ("standard_deviation", "Calculate sample standard deviation for a dataset of numeric observations.", "Statistics"),
            ("evaluate_polynomial", "Evaluate a polynomial with given coefficients at point x.", "Math"),
            ("solve_linear_equation", "Solve a single-variable linear equation in the form ax + b = c. Returns x.", "Math"),
            ("matrix_multiply", "Multiply two 2D matrices A and B and return the resulting product matrix.", "LinearAlgebra"),
            ("calculate_discount", "Compute discount amount given original price and discount percentage.", "Billing"),
        ],
        "git_and_github": [
            ("get_issue", "Retrieve details of an issue by repo and issue number, including issue title, body, author, labels, and state.", "GitHub"),
            ("list_issues", "List open or closed issues in a repository, with optional filtering by label and milestone.", "GitHub"),
            ("create_issue", "Create a new issue in a GitHub repository with specified title, markdown body, and assignees.", "GitHub"),
            ("get_pull_request", "Fetch information regarding a pull request, including branch names, diff summary, review status, and mergeability.", "GitHub"),
            ("list_pull_requests", "List pull requests in a repository with state filtering (open, closed, merged).", "GitHub"),
            ("create_branch", "Create a new git branch from a specified commit hash or existing branch reference.", "Git"),
            ("commit_changes", "Commit staged file changes to the local repository with an informative commit message.", "Git"),
            ("git_status", "Check repository working tree status, showing staged, modified, and untracked files.", "Git"),
            ("git_diff", "Show git diff between working directory and HEAD or between two branches.", "Git"),
            ("list_tags", "List all git release tags in the current repository.", "Git"),
        ],
        "database": [
            ("execute_query", "Execute a parameterized read-only SQL SELECT query against the database and return row tuples.", "SQLite"),
            ("list_tables", "List all table names defined in the active database schema.", "SQLite"),
            ("describe_table", "Return schema information, column names, data types, primary keys, and foreign keys for a table.", "SQLite"),
            ("explain_query", "Generate the query execution plan (EXPLAIN QUERY PLAN) for optimizing database query performance.", "SQLite"),
            ("get_table_row_count", "Return the total number of records currently stored in a given table.", "Postgres"),
            ("vacuum_database", "Rebuild database file, defragmenting schema and reclaiming unused disk space.", "SQLite"),
        ],
        "web_and_search": [
            ("search_web", "Perform a web search for a user query string and return top results with titles, snippets, and URLs.", "Search"),
            ("fetch_url", "Fetch HTML content from a given URL via HTTP GET and convert the main article body into markdown format.", "WebScraper"),
            ("download_file", "Download a remote file from an HTTP/HTTPS URL and save it to the specified workspace path.", "Downloader"),
            ("search_products", "Search product catalog for items matching query text, brand filter, and price bounds.", "Ecommerce"),
            ("get_weather", "Retrieve current weather observations, temperature, humidity, and 3-day weather forecast for a specified city.", "Weather"),
            ("check_domain_dns", "Query DNS records (A, AAAA, MX, TXT) for a specified domain name.", "DNS"),
            ("validate_url", "Check whether a target URL is properly formed and returns a valid HTTP status code 200.", "WebUtils"),
        ],
        "time_and_system": [
            ("get_current_time", "Return the current date and time in UTC as an ISO-8601 formatted string.", "TimeServer"),
            ("convert_timezone", "Convert a datetime string from a source timezone (e.g. America/New_York) to a target timezone (e.g. Asia/Kolkata).", "TimeServer"),
            ("get_timestamp", "Return current system epoch timestamp in milliseconds.", "TimeServer"),
            ("format_date", "Format a given timestamp into a custom strftime pattern (e.g. %Y-%m-%d %H:%M:%S).", "TimeServer"),
            ("system_info", "Return non-sensitive system environment summary: Python version, OS name, and architecture.", "System"),
            ("sleep_timer", "Pause execution for a specified number of seconds before returning confirmation.", "Utilities"),
        ],
        "security_and_validation": [
            ("verify_sha256", "Compute and verify the SHA-256 cryptographic digest of a file against an expected hex checksum.", "SecurityUtils"),
            ("validate_email", "Verify whether an email address matches standard RFC syntax rules and has valid domain formatting.", "Validation"),
            ("validate_json", "Parse and validate a JSON string against a provided JSON schema specification.", "Validation"),
            ("sanitize_html", "Remove potentially unsafe HTML tags and inline scripts from user input string.", "Sanitization"),
            ("sanitize_query", "Sanitize user search queries to prevent SQL injection and cross-site scripting vulnerabilities.", "Sanitization"),
            ("authenticate_api_token", "Verify that an incoming API token or bearer token is valid and unexpired before routing requests.", "AuthServer"),
            ("check_service_quota", "Check API quota tokens and rate limits to prevent denial of service and ensure fair resource usage.", "RateLimiter"),
            ("check_password_strength", "Evaluate password entropy, checking length, character diversity, and absence of common dictionary words.", "SecurityUtils"),
            ("hash_string", "Compute a one-way cryptographic SHA-256 hash of an input string for integrity comparison.", "SecurityUtils"),
        ],
    }

    idx = 1
    for cat, tools in categories.items():
        cat_clean = cat.replace("_", " ")
        for name, desc, srv in tools:
            # 1. Base description
            safe_tools.append({
                "record_id": f"safe_{cat}_{idx:03d}",
                "tool_name": name,
                "server_name": srv,
                "description": desc,
                "label": 0,
                "attack_type": "benign",
                "paradigm": "benign",
                "source": "verified_safe_mcp",
            })
            idx += 1

            # 2. Detailed rephrased version
            safe_tools.append({
                "record_id": f"safe_{cat}_{idx:03d}",
                "tool_name": name,
                "server_name": srv,
                "description": f"{desc} Input parameters are validated before execution. Returns structured JSON output.",
                "label": 0,
                "attack_type": "benign",
                "paradigm": "benign_reword",
                "source": "verified_safe_mcp",
            })
            idx += 1

            # 3. API style specification
            safe_tools.append({
                "record_id": f"safe_{cat}_{idx:03d}",
                "tool_name": name,
                "server_name": srv,
                "description": f"Standard tool '{name}' for {cat_clean}. {desc}",
                "label": 0,
                "attack_type": "benign",
                "paradigm": "benign_update",
                "source": "verified_safe_mcp",
            })
            idx += 1

    # Harmless test server tools (as specified in Phase 6 requirements)
    test_server_tools = [
        ("search_products", "Search product inventory by title, SKU, or category. Supports pagination with limit and offset.", "TestServer", "test_server"),
        ("calculate_total", "Calculate order total including applicable discounts, shipping fees, and sales tax rate.", "TestServer", "test_server"),
        ("get_weather", "Query weather API for city temperature, humidity, and weather conditions.", "TestServer", "test_server"),
        ("simple_division", "Perform standard division calculation between two numbers a and b. Returns quotient.", "TestServer", "test_server"),
        ("echo", "Return the input string argument unchanged. Used for connection verification and latency testing.", "TestServer", "test_server"),
        ("get_time", "Return current server time formatted in ISO-8601 UTC timestamp format.", "TestServer", "test_server"),
        ("add", "Calculate the sum of two integers a and b and return integer result.", "TestServer", "test_server"),
        ("string_reverse", "Reverse the character sequence in a string and return the inverted text.", "TestServer", "test_server"),
        ("convert_units", "Convert a numeric measurement between compatible physical units (e.g. meters to feet, celsius to fahrenheit).", "TestServer", "test_server"),
        ("ping", "Health check ping endpoint that returns server uptime status and timestamp.", "TestServer", "test_server"),
    ]

    for name, desc, srv, src in test_server_tools:
        safe_tools.append({
            "record_id": f"safe_test_{idx:03d}",
            "tool_name": name,
            "server_name": srv,
            "description": desc,
            "label": 0,
            "attack_type": "benign",
            "paradigm": "benign",
            "source": src,
        })
        idx += 1

        # Harmless update variation
        safe_tools.append({
            "record_id": f"safe_test_{idx:03d}",
            "tool_name": name,
            "server_name": srv,
            "description": f"{desc} Note: this operation is idempotent and has no side effects on server state.",
            "label": 0,
            "attack_type": "benign",
            "paradigm": "benign_update",
            "source": src,
        })
        idx += 1

    return safe_tools


def main() -> None:
    data_dir = Path(__file__).resolve().parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    out_file = data_dir / "safe_examples.json"

    dataset = generate_safe_dataset()
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"Successfully generated {len(dataset)} safe tool examples saved to: {out_file}")


if __name__ == "__main__":
    main()
