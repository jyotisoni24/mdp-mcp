"""Unit tests for Phase 8: Markov Decision Process (MDP) Implementation.

Verifies:
1. MDP policy artifacts exist and adhere to the schema.
2. Value iteration converges and computes bounded optimal values.
3. Q-learning policy converges to security-sound actions:
   - Approved baseline -> ALLOW
   - High risk -> BLOCK
   - Medium/uncertain risk -> QUARANTINE
   - Human review confirmed safe -> ALLOW
   - Human review confirmed malicious -> BLOCK
4. Safe simulator handles state transitions and rewards without executing code.
5. Comparative evaluation against static threshold policy produces empirical metrics.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from training.train_mdp import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_QUARANTINE,
    MCPSecuritySimulator,
    NUM_STATES,
    STATE_HIGH_RISK_UNVERIFIED,
    STATE_LOW_RISK_APPROVED,
    STATE_MEDIUM_RISK_UNVERIFIED,
    STATE_REVIEW_CONFIRMED_MALICIOUS,
    STATE_REVIEW_CONFIRMED_SAFE,
    STATE_TERMINAL,
    compare_policies,
    run_value_iteration,
    train_q_learning,
)

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
POLICY_FILE = MODELS_DIR / "mdp_policy.json"


def test_mdp_artifact_exists():
    """Verify models/mdp_policy.json was saved with expected structure."""
    assert POLICY_FILE.exists(), f"MDP policy file missing: {POLICY_FILE}"
    with open(POLICY_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "states" in data
    assert "actions" in data
    assert "value_iteration_policy" in data
    assert "q_learning_policy" in data
    assert "value_function" in data
    assert "q_table" in data


def test_value_iteration_convergence():
    """Verify value iteration produces expected state-value convergence."""
    V, policy = run_value_iteration()
    assert len(V) == NUM_STATES
    assert len(policy) == NUM_STATES
    assert V[STATE_TERMINAL] == 0.0
    # Approved baseline should have high positive value (+10)
    assert V[STATE_LOW_RISK_APPROVED] > 5.0
    assert policy[STATE_LOW_RISK_APPROVED] == ACTION_ALLOW


def test_q_learning_optimal_actions():
    """Verify Q-learning policy learns correct actions for critical states."""
    _, policy = train_q_learning(episodes=15000, seed=42)

    # State 0 (Approved) must ALLOW
    assert policy[STATE_LOW_RISK_APPROVED] == ACTION_ALLOW
    # State 2 (Medium risk) must QUARANTINE
    assert policy[STATE_MEDIUM_RISK_UNVERIFIED] == ACTION_QUARANTINE
    # State 3 (High risk) must BLOCK
    assert policy[STATE_HIGH_RISK_UNVERIFIED] == ACTION_BLOCK
    # State 5 (Review confirmed safe) must ALLOW
    assert policy[STATE_REVIEW_CONFIRMED_SAFE] == ACTION_ALLOW
    # State 6 (Review confirmed malicious) must BLOCK
    assert policy[STATE_REVIEW_CONFIRMED_MALICIOUS] == ACTION_BLOCK


def test_simulator_reward_dynamics():
    """Verify simulator reward transitions for correct vs breach actions."""
    sim = MCPSecuritySimulator(seed=123)

    # Allowing benign tool gives +10
    _, r_good_allow, done = sim.step(STATE_LOW_RISK_APPROVED, ACTION_ALLOW, true_label=0)
    assert r_good_allow == 10.0
    assert done is True

    # Allowing attack gives catastrophic -100
    _, r_bad_allow, done = sim.step(STATE_HIGH_RISK_UNVERIFIED, ACTION_ALLOW, true_label=1)
    assert r_bad_allow == -100.0
    assert done is True

    # Blocking attack gives +10
    _, r_good_block, done = sim.step(STATE_HIGH_RISK_UNVERIFIED, ACTION_BLOCK, true_label=1)
    assert r_good_block == 10.0
    assert done is True

    # Quarantine incurs -2 delay cost and does not terminate immediately
    next_s, r_quar, done = sim.step(STATE_MEDIUM_RISK_UNVERIFIED, ACTION_QUARANTINE, true_label=0)
    assert r_quar == -2.0
    assert done is False


def test_comparative_evaluation():
    """Verify policy comparison runs and outputs metrics."""
    V, policy = run_value_iteration()
    comp = compare_policies(policy, num_episodes=500, seed=42)

    assert comp["num_episodes"] == 500
    assert "mdp_mean_reward" in comp
    assert "static_mean_reward" in comp
    assert "reward_delta" in comp


def test_gateway_scenario_comparative_evaluation():
    """Verify the realistic gateway scenario comparison across the 7 cases."""
    from training.compare_gateway_policies import run_comparative_gateway_evaluation

    report = run_comparative_gateway_evaluation()
    assert report["status"] == "SUCCESS"
    assert report["total_scenarios"] == 7
    # Verify all scenarios have non-empty decisions
    for item in report["results"]:
        assert item["threshold_action"] in ["ALLOW", "QUARANTINE", "BLOCK"]
        assert item["mdp_action"] in ["ALLOW", "QUARANTINE", "BLOCK"]

