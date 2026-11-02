"""
Human Verification Workflow for MCP Benign Dataset.

Allows researchers to interactively inspect candidate MCP tool descriptions,
schemas, provenance, and safety flags before approving them as genuine benign
examples for training the MCP Security Gateway.

Guarantees:
- Never labels an example as benign without human verification.
- Displays descriptions in passive, inert isolation blocks (anti-prompt injection).
- Preserves verbatim description text.
- Maintains complete provenance and review audit logs.
"""

import os
import sys
import json
import csv
import argparse
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
CANDIDATES_JSON = os.path.join(DATA_DIR, "benign_candidates.json")
CANDIDATES_CSV = os.path.join(DATA_DIR, "benign_candidates.csv")
REVIEWED_JSON = os.path.join(DATA_DIR, "reviewed_benign.json")

def load_data():
    """Load candidates and existing reviewed benign records."""
    if not os.path.exists(CANDIDATES_JSON):
        print(f"Error: Candidates file not found at {CANDIDATES_JSON}")
        print("Run 'python training/collect_mcp_descriptions.py' first.")
        sys.exit(1)

    with open(CANDIDATES_JSON, "r", encoding="utf-8") as f:
        candidates = json.load(f)

    reviewed = []
    if os.path.exists(REVIEWED_JSON):
        try:
            with open(REVIEWED_JSON, "r", encoding="utf-8") as f:
                reviewed = json.load(f)
        except Exception:
            reviewed = []

    return candidates, reviewed

def save_data(candidates: list[dict], reviewed: list[dict]):
    """Persist updated candidate states and approved benign database."""
    # 1. Update candidates JSON
    with open(CANDIDATES_JSON, "w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2, ensure_ascii=False)

    # 2. Update candidates CSV
    csv_rows = []
    for c in candidates:
        props = list(c.get("input_schema", {}).get("properties", {}).keys())
        csv_rows.append({
            "candidate_id": c["candidate_id"],
            "tool_name": c["tool_name"],
            "server_name": c["server_name"],
            "category": c.get("category", "General"),
            "tool_description": c["tool_description"],
            "parameters": ", ".join(props),
            "repo_url": c.get("provenance", {}).get("repo_url", ""),
            "commit_hash": c.get("provenance", {}).get("commit_hash", ""),
            "version": c.get("provenance", {}).get("server_version", ""),
            "license": c.get("provenance", {}).get("license", ""),
            "verification_status": c["verification_status"],
            "safety_flags": "; ".join(c.get("quality_and_safety_checks", {}).get("suspicious_instruction_flags", [])) or "none",
            "near_duplicates": len(c.get("quality_and_safety_checks", {}).get("near_duplicates", []))
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

    # 3. Update reviewed benign JSON
    with open(REVIEWED_JSON, "w", encoding="utf-8") as f:
        json.dump(reviewed, f, indent=2, ensure_ascii=False)

    print("\n[OK] Progress saved to candidates and reviewed_benign databases.")

def display_status(candidates: list[dict], reviewed: list[dict]):
    """Display progress overview and counts."""
    total = len(candidates)
    pending = sum(1 for c in candidates if c.get("verification_status") == "pending_review")
    approved = sum(1 for c in candidates if c.get("verification_status") == "approved_benign")
    rejected = sum(1 for c in candidates if c.get("verification_status") == "rejected")

    print("\n" + "=" * 70)
    print("MCP BENIGN DATASET VERIFICATION STATUS")
    print("=" * 70)
    print(f"Total Candidate Pool:       {total}")
    print(f"  * Pending Review:         {pending} ({pending/total*100:.1f}%)" if total else "0")
    print(f"  * Approved Benign:        {approved} ({approved/total*100:.1f}%)" if total else "0")
    print(f"  * Rejected:               {rejected} ({rejected/total*100:.1f}%)" if total else "0")
    print(f"Verified Records in Store:  {len(reviewed)}")
    print("=" * 70 + "\n")

def display_candidate(cand: dict, index: int, total: int):
    """Render an individual candidate safely with clear visual boundaries."""
    prov = cand.get("provenance", {})
    safety = cand.get("quality_and_safety_checks", {})
    schema = cand.get("input_schema", {})
    props = schema.get("properties", {})
    reqs = schema.get("required", [])

    print("\n" + "=" * 80)
    print(f"CANDIDATE [{index + 1}/{total}]: {cand['candidate_id']}")
    print("=" * 80)
    print(f"Server Name:        {cand['server_name']} (Category: {cand.get('category', 'N/A')})")
    print(f"Server Description: {cand.get('server_level_metadata', {}).get('server_description', 'N/A')}")
    print(f"Repository:         {prov.get('repo_url', 'N/A')}")
    print(f"Commit Hash:        {prov.get('commit_hash', 'N/A')}")
    print(f"Source Location:    {prov.get('server_path', '')}/{prov.get('source_file', '')}")
    print(f"Version & License:  v{prov.get('server_version', 'N/A')} | License: {prov.get('license', 'N/A')}")
    print(f"Verification State: {cand.get('verification_status')}")
    print("-" * 80)
    print(f"Tool Identifier:    {cand['tool_name']}")
    print("-" * 80)

    print(">>> PASSIVE / UNTRUSTED TOOL DESCRIPTION STRING (VERBATIM) <<<")
    print("-" * 80)
    desc = cand.get("tool_description", "")
    print(desc if desc else "[NO DESCRIPTION PROVIDED]")
    print("-" * 80)

    print("Input Schema Properties:")
    if props:
        for p_name, p_info in props.items():
            req_marker = "[REQUIRED]" if p_name in reqs else "[optional]"
            p_desc = p_info.get("description", "")
            p_type = p_info.get("type", "any")
            print(f"  * {p_name} ({p_type}) {req_marker}: {p_desc}")
    else:
        print("  * (No input parameters)")

    print("-" * 80)
    print("Automated Quality & Safety Scan Results:")
    flags = safety.get("suspicious_instruction_flags", [])
    if flags:
        print("  [!] WARNING - POTENTIAL INSTRUCTION OVERRIDE / DIRECTIVE DETECTED:")
        for fl in flags:
            print(f"      - {fl}")
    else:
        print("  [OK] No prompt override directives detected.")

    near_dups = safety.get("near_duplicates", [])
    if near_dups:
        print(f"  [!] Near-duplicates detected ({len(near_dups)}):")
        for nd in near_dups:
            print(f"      - Matches {nd['candidate_id']} ({nd['similarity']*100:.0f}% overlap)")
    else:
        print("  [OK] No near-duplicate collisions.")
    print("=" * 80)

def review_loop(reviewer_name: str):
    """Main interactive human review terminal loop."""
    candidates, reviewed = load_data()
    pending = [c for c in candidates if c.get("verification_status") == "pending_review"]

    if not pending:
        print("All candidates have been reviewed! No pending tools.")
        display_status(candidates, reviewed)
        return

    print(f"\nWelcome {reviewer_name}. You have {len(pending)} candidate tools to review.")
    print("Commands: [a] Approve as benign | [r] Reject | [s] Skip | [q] Save & Quit\n")

    reviewed_ids = {r["candidate_id"] for r in reviewed}

    for idx, cand in enumerate(candidates):
        if cand.get("verification_status") != "pending_review":
            continue

        display_candidate(cand, idx, len(candidates))

        while True:
            choice = input("\nDecision [a/r/s/q] > ").strip().lower()

            if choice == "a":
                notes = input("Optional reviewer notes (press Enter to skip): ").strip()
                cand["verification_status"] = "approved_benign"
                cand["reviewer_notes"] = notes or "Manually verified genuine benign MCP tool description."
                cand["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                cand["reviewed_by"] = reviewer_name

                # Add to reviewed database
                if cand["candidate_id"] not in reviewed_ids:
                    reviewed.append(cand)
                    reviewed_ids.add(cand["candidate_id"])

                print(f"[OK] APPROVED: {cand['candidate_id']} marked as benign.")
                break

            elif choice == "r":
                reason = input("Enter rejection reason (required): ").strip()
                while not reason:
                    reason = input("Rejection reason cannot be empty: ").strip()

                cand["verification_status"] = "rejected"
                cand["reviewer_notes"] = f"REJECTED: {reason}"
                cand["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                cand["reviewed_by"] = reviewer_name

                # Remove from reviewed store if previously present
                reviewed = [r for r in reviewed if r["candidate_id"] != cand["candidate_id"]]
                reviewed_ids.discard(cand["candidate_id"])

                print(f"[REJECTED] {cand['candidate_id']}.")
                break

            elif choice == "s":
                print(f"[-] SKIPPED: {cand['candidate_id']} left pending.")
                break

            elif choice == "q":
                save_data(candidates, reviewed)
                print("Exiting review session. Goodbye!")
                return

            else:
                print("Invalid command. Choose 'a' (approve), 'r' (reject), 's' (skip), or 'q' (quit).")

    save_data(candidates, reviewed)
    print("\nReview session complete!")
    display_status(candidates, reviewed)

def main():
    parser = argparse.ArgumentParser(description="Human review CLI for benign MCP tool descriptions.")
    parser.add_argument("--status", "-s", action="store_true", help="Display verification counts.")
    parser.add_argument("--reviewer", "-r", default="researcher", help="Reviewer identifier/initials.")
    parser.add_argument("--list", "-l", action="store_true", help="List all candidate records.")
    args = parser.parse_args()

    candidates, reviewed = load_data()

    if args.status:
        display_status(candidates, reviewed)
        return

    if args.list:
        print(f"\n{'ID':<35} {'SERVER':<15} {'STATUS':<18} {'FLAGS'}")
        print("-" * 80)
        for c in candidates:
            flags_cnt = len(c.get("quality_and_safety_checks", {}).get("suspicious_instruction_flags", []))
            print(f"{c['candidate_id']:<35} {c['server_name']:<15} {c['verification_status']:<18} {flags_cnt} flag(s)")
        print()
        return

    review_loop(reviewer_name=args.reviewer)

if __name__ == "__main__":
    main()
