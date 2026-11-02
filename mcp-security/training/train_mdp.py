"""Markov Decision Process (MDP) for Sequential Tool Decision-Making.

Models the sequential decision problem of tool authorization under uncertainty:
    M = (S, A, P, R, gamma)

States (S):
    0: LOW_RISK_APPROVED          (Low ML risk, baseline approved)
    1: LOW_RISK_UNVERIFIED        (Low ML risk, unapproved update/drift)
    2: MEDIUM_RISK_UNVERIFIED     (Uncertain ML risk, unapproved)
    3: HIGH_RISK_UNVERIFIED       (High ML risk, unapproved)
    4: QUARANTINED_AWAITING_REVIEW (Held in quarantine, pending analyst audit)
    5: REVIEW_CONFIRMED_SAFE      (Analyst confirmed benign)
    6: REVIEW_CONFIRMED_MALICIOUS (Analyst confirmed attack)
    7: TERMINAL                   (Decision finalized)

Actions (A):
    0: ALLOW
    1: QUARANTINE
    2: BLOCK

Rewards (R):
    - Correctly allowing legitimate tool: +10.0
    - Correctly blocking malicious tool : +10.0
    - Allowing malicious tool (Breach)  : -100.0
    - Blocking legitimate tool (Denial) : -20.0
    - Quarantine delay / review cost    : -2.0
    - Redundant quarantine penalty      : -5.0

Computes optimal policies via both Value Iteration and Q-Learning in a safe simulator.
Compares the MDP policy against the static threshold policy.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
import random
import sys
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_mdp")

# State space
STATE_LOW_RISK_APPROVED = 0
STATE_LOW_RISK_UNVERIFIED = 1
STATE_MEDIUM_RISK_UNVERIFIED = 2
STATE_HIGH_RISK_UNVERIFIED = 3
STATE_QUARANTINED_AWAITING_REVIEW = 4
STATE_REVIEW_CONFIRMED_SAFE = 5
STATE_REVIEW_CONFIRMED_MALICIOUS = 6
STATE_TERMINAL = 7

NUM_STATES = 8

STATE_NAMES = {
    STATE_LOW_RISK_APPROVED: "LOW_RISK_APPROVED",
    STATE_LOW_RISK_UNVERIFIED: "LOW_RISK_UNVERIFIED",
    STATE_MEDIUM_RISK_UNVERIFIED: "MEDIUM_RISK_UNVERIFIED",
    STATE_HIGH_RISK_UNVERIFIED: "HIGH_RISK_UNVERIFIED",
    STATE_QUARANTINED_AWAITING_REVIEW: "QUARANTINED_AWAITING_REVIEW",
    STATE_REVIEW_CONFIRMED_SAFE: "REVIEW_CONFIRMED_SAFE",
    STATE_REVIEW_CONFIRMED_MALICIOUS: "REVIEW_CONFIRMED_MALICIOUS",
    STATE_TERMINAL: "TERMINAL",
}

# Action space
ACTION_ALLOW = 0
ACTION_QUARANTINE = 1
ACTION_BLOCK = 2

NUM_ACTIONS = 3

ACTION_NAMES = {
    ACTION_ALLOW: "ALLOW",
    ACTION_QUARANTINE: "QUARANTINE",
    ACTION_BLOCK: "BLOCK",
}

# Reward matrix constants
R_CORRECT_ALLOW = 10.0
R_CORRECT_BLOCK = 10.0
R_BREACH_PENALTY = -100.0
R_FALSE_BLOCK_PENALTY = -20.0
R_QUARANTINE_COST = -2.0
R_INVALID_ACTION = -5.0


@dataclass
class SimulationEpisodeResult:
    initial_state: int
    true_label: int  # 0 = Benign, 1 = Attack
    actions_taken: list[int]
    total_reward: float
    final_action: int
    resolved_via_review: bool


class MCPSecuritySimulator:
    """Safe, isolated environment simulator for MDP exploration and policy training.

    Guarantees: No live MCP tool execution occurs during exploration.
    """

    def __init__(self, review_accuracy: float = 0.98, seed: int = 42) -> None:
        self.review_accuracy = review_accuracy
        self.rng = random.Random(seed)

    def sample_episode(self, state: int, true_label: int | None = None) -> tuple[int, int]:
        """Initialize an episode with an initial state and ground-truth label."""
        if true_label is None:
            # Realistic ground-truth probabilities given the observable ML state
            if state == STATE_LOW_RISK_APPROVED:
                true_label = 0  # Approved baseline is benign
            elif state == STATE_LOW_RISK_UNVERIFIED:
                true_label = 1 if self.rng.random() < 0.05 else 0
            elif state == STATE_MEDIUM_RISK_UNVERIFIED:
                true_label = 1 if self.rng.random() < 0.50 else 0
            elif state == STATE_HIGH_RISK_UNVERIFIED:
                true_label = 1 if self.rng.random() < 0.95 else 0
            else:
                true_label = 0

        return state, true_label

    def step(self, state: int, action: int, true_label: int) -> tuple[int, float, bool]:
        """Execute action in simulator and return (next_state, reward, is_done)."""
        # Terminal state check
        if state == STATE_TERMINAL:
            return STATE_TERMINAL, 0.0, True

        # Action: ALLOW
        if action == ACTION_ALLOW:
            if true_label == 0:
                # Correctly allowed benign tool
                return STATE_TERMINAL, R_CORRECT_ALLOW, True
            else:
                # Catastrophic failure: allowed malicious attack!
                return STATE_TERMINAL, R_BREACH_PENALTY, True

        # Action: BLOCK
        elif action == ACTION_BLOCK:
            if true_label == 1:
                # Correctly blocked attack
                return STATE_TERMINAL, R_CORRECT_BLOCK, True
            else:
                # Disruption: falsely blocked legitimate tool
                return STATE_TERMINAL, R_FALSE_BLOCK_PENALTY, True

        # Action: QUARANTINE
        elif action == ACTION_QUARANTINE:
            if state in [
                STATE_LOW_RISK_UNVERIFIED,
                STATE_MEDIUM_RISK_UNVERIFIED,
                STATE_HIGH_RISK_UNVERIFIED,
            ]:
                # Enter quarantine, incur small delay cost
                return STATE_QUARANTINED_AWAITING_REVIEW, R_QUARANTINE_COST, False

            elif state == STATE_QUARANTINED_AWAITING_REVIEW:
                # Human review resolves the state
                is_correct = self.rng.random() < self.review_accuracy
                if true_label == 0:
                    next_state = STATE_REVIEW_CONFIRMED_SAFE if is_correct else STATE_REVIEW_CONFIRMED_MALICIOUS
                else:
                    next_state = STATE_REVIEW_CONFIRMED_MALICIOUS if is_correct else STATE_REVIEW_CONFIRMED_SAFE
                return next_state, R_QUARANTINE_COST, False

            elif state in [STATE_REVIEW_CONFIRMED_SAFE, STATE_REVIEW_CONFIRMED_MALICIOUS]:
                # Redundant quarantine on already reviewed state
                return state, R_INVALID_ACTION, False

            elif state == STATE_LOW_RISK_APPROVED:
                # Unnecessary delay on verified baseline
                return state, R_QUARANTINE_COST, False

        return STATE_TERMINAL, R_INVALID_ACTION, True


def run_value_iteration(
    gamma: float = 0.95,
    theta: float = 1e-5,
) -> tuple[np.ndarray, np.ndarray]:
    """Solve the MDP using Value Iteration dynamic programming.

    Returns:
        V: Value function array of shape (NUM_STATES,)
        policy: Optimal action array of shape (NUM_STATES,)
    """
    V = np.zeros(NUM_STATES)
    policy = np.zeros(NUM_STATES, dtype=int)

    # Transition and expected immediate reward model
    # For each state, we model P(true_label=1)
    p_attack = {
        STATE_LOW_RISK_APPROVED: 0.0,
        STATE_LOW_RISK_UNVERIFIED: 0.05,
        STATE_MEDIUM_RISK_UNVERIFIED: 0.50,
        STATE_HIGH_RISK_UNVERIFIED: 0.95,
        STATE_QUARANTINED_AWAITING_REVIEW: 0.50,
        STATE_REVIEW_CONFIRMED_SAFE: 0.01,
        STATE_REVIEW_CONFIRMED_MALICIOUS: 0.99,
        STATE_TERMINAL: 0.0,
    }

    while True:
        delta = 0.0
        for s in range(NUM_STATES):
            if s == STATE_TERMINAL:
                continue

            q_values = np.zeros(NUM_ACTIONS)
            p_mal = p_attack[s]
            p_safe = 1.0 - p_mal

            # Action 0: ALLOW -> Terminal
            q_values[ACTION_ALLOW] = p_safe * R_CORRECT_ALLOW + p_mal * R_BREACH_PENALTY

            # Action 2: BLOCK -> Terminal
            q_values[ACTION_BLOCK] = p_mal * R_CORRECT_BLOCK + p_safe * R_FALSE_BLOCK_PENALTY

            # Action 1: QUARANTINE
            if s in [STATE_LOW_RISK_UNVERIFIED, STATE_MEDIUM_RISK_UNVERIFIED, STATE_HIGH_RISK_UNVERIFIED]:
                q_values[ACTION_QUARANTINE] = R_QUARANTINE_COST + gamma * V[STATE_QUARANTINED_AWAITING_REVIEW]
            elif s == STATE_QUARANTINED_AWAITING_REVIEW:
                # Transitions to confirmed states via analyst review
                p_safe_conf = p_safe * 0.98 + p_mal * 0.02
                p_mal_conf = p_mal * 0.98 + p_safe * 0.02
                expected_next = p_safe_conf * V[STATE_REVIEW_CONFIRMED_SAFE] + p_mal_conf * V[STATE_REVIEW_CONFIRMED_MALICIOUS]
                q_values[ACTION_QUARANTINE] = R_QUARANTINE_COST + gamma * expected_next
            elif s == STATE_LOW_RISK_APPROVED:
                q_values[ACTION_QUARANTINE] = R_QUARANTINE_COST + gamma * V[s]
            else:
                q_values[ACTION_QUARANTINE] = R_INVALID_ACTION + gamma * V[s]

            best_val = np.max(q_values)
            delta = max(delta, abs(best_val - V[s]))
            V[s] = best_val
            policy[s] = int(np.argmax(q_values))

        if delta < theta:
            break

    return V, policy


def train_q_learning(
    episodes: int = 15000,
    alpha_start: float = 0.2,
    alpha_end: float = 0.02,
    gamma: float = 0.95,
    epsilon_start: float = 0.3,
    epsilon_end: float = 0.01,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """Train MDP policy using Model-Free Q-Learning with learning rate decay in safe simulator."""
    sim = MCPSecuritySimulator(seed=seed)
    Q = np.zeros((NUM_STATES, NUM_ACTIONS))
    rng = random.Random(seed)

    start_states = [
        STATE_LOW_RISK_APPROVED,
        STATE_LOW_RISK_UNVERIFIED,
        STATE_MEDIUM_RISK_UNVERIFIED,
        STATE_HIGH_RISK_UNVERIFIED,
    ]

    for ep in range(episodes):
        decay_factor = 1.0 - (ep / episodes)
        alpha = max(alpha_end, alpha_start * decay_factor)
        epsilon = max(epsilon_end, epsilon_start * decay_factor)

        init_state = rng.choice(start_states)
        state, true_label = sim.sample_episode(init_state)

        done = False
        while not done:
            # Epsilon-greedy action selection
            if rng.random() < epsilon:
                action = rng.randint(0, NUM_ACTIONS - 1)
            else:
                action = int(np.argmax(Q[state]))

            next_state, reward, done = sim.step(state, action, true_label)

            # Q-learning update equation:
            # Q(s, a) <- Q(s, a) + alpha * [r + gamma * max_a' Q(s', a') - Q(s, a)]
            best_next = 0.0 if done else np.max(Q[next_state])
            td_target = reward + gamma * best_next
            Q[state, action] += alpha * (td_target - Q[state, action])

            state = next_state

    learned_policy = np.argmax(Q, axis=1)
    return Q, learned_policy


def compare_policies(
    mdp_policy: np.ndarray,
    num_episodes: int = 2000,
    seed: int = 999,
) -> dict[str, Any]:
    """Empirically compare MDP Sequential Policy vs. Static Threshold Policy."""
    sim = MCPSecuritySimulator(seed=seed)
    rng = random.Random(seed)

    start_states = [
        STATE_LOW_RISK_APPROVED,
        STATE_LOW_RISK_UNVERIFIED,
        STATE_MEDIUM_RISK_UNVERIFIED,
        STATE_HIGH_RISK_UNVERIFIED,
    ]

    # Benchmark: Static Threshold Policy
    # - Approved -> ALLOW
    # - Low unverified -> QUARANTINE
    # - Medium unverified -> QUARANTINE
    # - High unverified -> BLOCK
    static_policy = {
        STATE_LOW_RISK_APPROVED: ACTION_ALLOW,
        STATE_LOW_RISK_UNVERIFIED: ACTION_QUARANTINE,
        STATE_MEDIUM_RISK_UNVERIFIED: ACTION_QUARANTINE,
        STATE_HIGH_RISK_UNVERIFIED: ACTION_BLOCK,
        STATE_QUARANTINED_AWAITING_REVIEW: ACTION_QUARANTINE,
        STATE_REVIEW_CONFIRMED_SAFE: ACTION_ALLOW,
        STATE_REVIEW_CONFIRMED_MALICIOUS: ACTION_BLOCK,
    }

    results = {"mdp": [], "static": []}

    for ep in range(num_episodes):
        init_s = rng.choice(start_states)

        # Run MDP Policy
        s, true_lbl = sim.sample_episode(init_s)
        total_r_mdp = 0.0
        done = False
        while not done:
            action = int(mdp_policy[s])
            s, r, done = sim.step(s, action, true_lbl)
            total_r_mdp += r
        results["mdp"].append({"reward": total_r_mdp, "breach": (total_r_mdp <= -50)})

        # Run Static Policy
        s, _ = sim.sample_episode(init_s, true_label=true_lbl)
        total_r_static = 0.0
        done = False
        while not done:
            action = static_policy[s]
            s, r, done = sim.step(s, action, true_lbl)
            total_r_static += r
        results["static"].append({"reward": total_r_static, "breach": (total_r_static <= -50)})

    mdp_rewards = [x["reward"] for x in results["mdp"]]
    static_rewards = [x["reward"] for x in results["static"]]
    mdp_breaches = sum(1 for x in results["mdp"] if x["breach"])
    static_breaches = sum(1 for x in results["static"] if x["breach"])

    return {
        "num_episodes": num_episodes,
        "mdp_mean_reward": float(np.mean(mdp_rewards)),
        "static_mean_reward": float(np.mean(static_rewards)),
        "mdp_total_reward": float(np.sum(mdp_rewards)),
        "static_total_reward": float(np.sum(static_rewards)),
        "mdp_breach_count": mdp_breaches,
        "static_breach_count": static_breaches,
        "reward_delta": float(np.mean(mdp_rewards) - np.mean(static_rewards)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate the MDP security decision policy.")
    base_dir = Path(__file__).resolve().parent.parent
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=base_dir / "models",
        help="Directory to save MDP policy artifacts",
    )
    args = parser.parse_args()

    logger.info("Computing optimal MDP policy via Value Iteration...")
    V, vi_policy = run_value_iteration()

    logger.info("Training MDP policy via Model-Free Q-Learning in safe simulator...")
    Q, q_policy = train_q_learning(episodes=20000)

    # Serialize policy and Q-table
    args.output_dir.mkdir(parents=True, exist_ok=True)
    policy_file = args.output_dir / "mdp_policy.json"
    artifact = {
        "states": STATE_NAMES,
        "actions": ACTION_NAMES,
        "value_iteration_policy": {STATE_NAMES[s]: ACTION_NAMES[a] for s, a in enumerate(vi_policy)},
        "q_learning_policy": {STATE_NAMES[s]: ACTION_NAMES[a] for s, a in enumerate(q_policy)},
        "value_function": {STATE_NAMES[s]: round(float(v), 2) for s, v in enumerate(V)},
        "q_table": {STATE_NAMES[s]: [round(float(q), 2) for q in Q[s]] for s in range(NUM_STATES)},
    }
    with open(policy_file, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    logger.info(f"MDP artifacts saved to: {policy_file}")

    # Comparative evaluation
    logger.info("Running comparative evaluation: MDP Policy vs. Static Threshold Policy (2000 episodes)...")
    comp = compare_policies(q_policy, num_episodes=2000)

    # Print clean report
    print("\n" + "=" * 70)
    print("      MDP SEQUENTIAL DECISION-MAKING EVALUATION & COMPARISON")
    print("=" * 70)
    print("Optimal Actions Learned per State:")
    for s in range(NUM_STATES - 1):
        sname = STATE_NAMES[s]
        act_vi = ACTION_NAMES[vi_policy[s]]
        act_q = ACTION_NAMES[q_policy[s]]
        val = V[s]
        print(f"  [{s}] {sname:<32} -> Action: {act_q:<10} (V*={val:+.1f})")
    print("-" * 70)
    print(f"Simulation Comparison over {comp['num_episodes']} Independent Episodes:")
    print(f"  MDP Policy Average Reward            : {comp['mdp_mean_reward']:+.2f}")
    print(f"  Static Threshold Average Reward      : {comp['static_mean_reward']:+.2f}")
    print(f"  Reward Delta (MDP vs Static)         : {comp['reward_delta']:+.2f}")
    print(f"  Breach Count (Malicious Allowed)     : MDP = {comp['mdp_breach_count']}, Static = {comp['static_breach_count']}")
    print("-" * 70)
    print("Empirical Finding:")
    if comp["reward_delta"] > 0:
        print("  -> MDP achieves HIGHER cumulative reward by optimally balancing review delay")
        print("     costs against catastrophic breach penalties under uncertainty.")
    else:
        print("  -> MDP performs comparably to the static threshold baseline in this setting.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
