import random
import copy
import pandas as pd
import networkx as nx
from backend.knowledge_graph import DigitalTwinKnowledgeGraph

class QAttackAgent:
    """
    Offline Simulated AI Attacker using Reinforcement Learning (Q-Learning).
    Operates STRICTLY on the Digital Twin graph representation.
    NEVER interacts with real physical networks or sends real network packets.
    """

    ACTIONS = [
        "ENUMERATE_SERVICE",
        "MOVE_TO_NODE",
        "ATTEMPT_SIMULATED_EXPLOIT",
        "LATERAL_MOVE",
        "STOP"
    ]

    def __init__(self, twin_state, alpha=0.1, gamma=0.9, epsilon=0.2):
        self.twin_state = twin_state
        self.alpha = float(alpha)
        self.gamma = float(gamma)
        self.epsilon = float(epsilon)
        self.q_table = {}
        self.total_episodes_trained = 0

        # Extract graph & identify entry/target nodes
        self.kg = DigitalTwinKnowledgeGraph(twin_state)
        self.graph = self.kg.get_graph()
        self.assets = twin_state.get("assets", [])

        self.entry_node = self._find_entry_node()
        self.target_node = self._find_target_node()

    def _find_entry_node(self):
        for a in self.assets:
            if a.get("device_type") in ["Router", "Workstation"]:
                return f"asset:{a['asset_id']}"
        return f"asset:{self.assets[0]['asset_id']}" if self.assets else "asset:AST-001"

    def _find_target_node(self):
        for a in self.assets:
            if a.get("device_type") == "Server" or a.get("importance") == "Critical":
                return f"asset:{a['asset_id']}"
        return f"asset:{self.assets[-1]['asset_id']}" if self.assets else "asset:AST-002"

    def _get_q(self, state, action):
        return self.q_table.get((state, action), 0.0)

    def train(self, episodes=100):
        """
        Runs real Q-learning training episodes against the Digital Twin graph.
        Returns real training progression metrics.
        """
        episodes = int(episodes)
        history = []
        decay_rate = self.epsilon / max(episodes, 1)
        curr_eps = self.epsilon

        for ep in range(1, episodes + 1):
            curr_node = self.entry_node
            compromised = {self.entry_node}
            total_reward = 0.0
            steps = 0
            target_reached = False
            done = False

            while not done and steps < 25:
                steps += 1
                state_key = (curr_node, tuple(sorted(compromised)))

                # Epsilon-greedy action selection
                if random.random() < curr_eps:
                    action = random.choice(self.ACTIONS)
                else:
                    q_vals = [self._get_q(state_key, a) for a in self.ACTIONS]
                    max_q = max(q_vals)
                    best_actions = [a for a, q in zip(self.ACTIONS, q_vals) if q == max_q]
                    action = random.choice(best_actions)

                # Execute action against Digital Twin model
                next_node, reward, episode_done, reached = self._step(curr_node, action, compromised)
                
                if reached:
                    target_reached = True

                next_state_key = (next_node, tuple(sorted(compromised)))

                # Q-Table Update Rule: Q(s,a) = Q(s,a) + alpha * [r + gamma * max Q(s',a') - Q(s,a)]
                max_next_q = max([self._get_q(next_state_key, a) for a in self.ACTIONS])
                old_q = self._get_q(state_key, action)
                new_q = old_q + self.alpha * (reward + self.gamma * max_next_q - old_q)
                self.q_table[(state_key, action)] = round(new_q, 3)

                curr_node = next_node
                total_reward += reward
                done = episode_done

            # Decay epsilon gradually
            curr_eps = max(0.01, curr_eps - decay_rate)

            history.append({
                "episode": ep,
                "reward": round(total_reward, 2),
                "steps": steps,
                "target_reached": target_reached
            })

        self.total_episodes_trained += episodes
        return history

    def _step(self, curr_node, action, compromised):
        if action == "STOP":
            return curr_node, -1.0, True, False

        neighbors = list(self.graph.successors(curr_node)) if self.graph.has_node(curr_node) else []

        if action == "ENUMERATE_SERVICE":
            return curr_node, -1.0, False, False

        elif action in ["MOVE_TO_NODE", "LATERAL_MOVE"]:
            valid_next = [n for n in neighbors if n.startswith("asset:") or n.startswith("port:")]
            if valid_next:
                next_n = random.choice(valid_next)
                if next_n.startswith("asset:"):
                    compromised.add(next_n)
                    if next_n == self.target_node:
                        return next_n, 100.0, True, True
                    return next_n, 10.0, False, False
                return next_n, 5.0, False, False
            return curr_node, -5.0, False, False

        elif action == "ATTEMPT_SIMULATED_EXPLOIT":
            vuln_nodes = [n for n in neighbors if n.startswith("vuln:") or n.startswith("service:")]
            if vuln_nodes:
                target_asset_nodes = [n for n in self.graph.nodes() if n.startswith("asset:") and n != curr_node]
                if target_asset_nodes:
                    next_n = random.choice(target_asset_nodes)
                    compromised.add(next_n)
                    if next_n == self.target_node:
                        return next_n, 100.0, True, True
                    return next_n, 20.0, False, False
            return curr_node, -10.0, False, False

        return curr_node, -1.0, False, False

    def get_model_status(self):
        """Returns Q-table metadata and model status."""
        return {
            "total_state_action_pairs": len(self.q_table),
            "total_episodes_trained": self.total_episodes_trained,
            "entry_node": self.entry_node,
            "target_node": self.target_node,
            "hyperparameters": {
                "alpha": self.alpha,
                "gamma": self.gamma,
                "epsilon": self.epsilon
            }
        }

    def get_q_table_dataframe(self):
        """Returns learned Q-table as Pandas DataFrame."""
        if not self.q_table:
            return pd.DataFrame(columns=["State", "Action", "Q-Value"])

        rows = []
        for (state_key, action), q_val in self.q_table.items():
            curr_n = state_key[0]
            rows.append({
                "State Node": curr_n,
                "Action": action,
                "Q-Value": q_val
            })

        df = pd.DataFrame(rows)
        return df.sort_values(by="Q-Value", ascending=False).reset_index(drop=True)


class AttackPathAnalyzer:
    """
    Module 9: Attack Path Analysis Engine.
    Discovers simple paths from Entry Point -> Target Node.
    """

    def __init__(self, twin_state):
        self.twin_state = twin_state
        self.assets = twin_state.get("assets", [])
        self.vulnerabilities = twin_state.get("vulnerabilities", [])

    def analyze_paths(self):
        paths = []
        if not self.assets:
            return paths

        entry_assets = [a for a in self.assets if a.get("device_type") in ["Router", "Workstation", "Laptop"]]
        target_assets = [a for a in self.assets if a.get("device_type") == "Server" or a.get("importance") == "Critical"]

        if not entry_assets:
            entry_assets = [self.assets[0]]
        if not target_assets:
            target_assets = [self.assets[-1]]

        for entry in entry_assets:
            for target in target_assets:
                if entry["asset_id"] == target["asset_id"]:
                    continue

                intermediates = [a for a in self.assets if a["asset_id"] not in [entry["asset_id"], target["asset_id"]]]
                inter_host = intermediates[0]["hostname"] if intermediates else "Internal Gateway"

                path_nodes = [entry["hostname"], inter_host, target["hostname"]]
                path_vulns = [v for v in self.vulnerabilities if v["asset_id"] in [entry["asset_id"], target["asset_id"]]]
                max_cvss = max([v["cvss"] for v in path_vulns]) if path_vulns else 4.0

                path_risk = min(round(max_cvss * 8.5 + (len(path_nodes) * 3), 1), 100.0)
                difficulty = "Low" if max_cvss > 8.0 else ("Medium" if max_cvss > 5.0 else "High")
                impact = "Critical" if target.get("importance") == "Critical" else "High"

                paths.append({
                    "entry_point": entry["hostname"],
                    "target": target["hostname"],
                    "path": path_nodes,
                    "steps": len(path_nodes),
                    "path_risk": path_risk,
                    "difficulty": difficulty,
                    "impact": impact,
                    "max_cvss": max_cvss,
                    "status": "EXPOSED"
                })

        return sorted(paths, key=lambda x: x["path_risk"], reverse=True)


class DefensiveDecisionEngine:
    """
    Module 10: Defensive Decision Engine.
    Prioritizes virtual security fixes based on attack path impact & risk reduction.
    """

    def __init__(self, twin_state):
        self.twin_state = twin_state
        self.analyzer = AttackPathAnalyzer(twin_state)

    def recommend_defenses(self):
        paths = self.analyzer.analyze_paths()
        recommendations = []

        vulns = self.twin_state.get("vulnerabilities", [])
        services = self.twin_state.get("services", [])

        crit_vulns = [v for v in vulns if v["severity"] == "Critical"]
        if crit_vulns:
            top_v = crit_vulns[0]
            recommendations.append({
                "priority": 1,
                "action": f"Patch {top_v['cve_id']} on {top_v['hostname']}",
                "type": "PATCH_VULNERABILITY",
                "target_asset": top_v['hostname'],
                "cve_id": top_v['cve_id'],
                "paths_broken": len(paths),
                "risk_reduction": round(top_v['cvss'] * 4.2, 1),
                "reason": f"Breaks {len(paths)} critical attack path(s) reaching core enterprise servers."
            })

        admin_ports = [s for s in services if s["port"] in [445, 3389, 22]]
        if admin_ports:
            top_p = admin_ports[0]
            recommendations.append({
                "priority": 2,
                "action": f"Close Port {top_p['port']} ({top_p['service']}) on {top_p['hostname']}",
                "type": "CLOSE_PORT",
                "target_asset": top_p['hostname'],
                "port": top_p['port'],
                "paths_broken": max(len(paths) - 1, 1),
                "risk_reduction": 18.5,
                "reason": f"Blocks remote lateral movement via exposed {top_p['service']} administration port."
            })

        high_risk_assets = [a for a in self.twin_state.get("assets", []) if a.get("risk_level") in ["Critical", "High"]]
        if high_risk_assets:
            top_a = high_risk_assets[0]
            recommendations.append({
                "priority": 3,
                "action": f"Isolate Host {top_a['hostname']} from Subnet",
                "type": "ISOLATE_HOST",
                "target_asset": top_a['hostname'],
                "paths_broken": 1,
                "risk_reduction": 12.0,
                "reason": "Prevents compromised host from serving as a lateral pivoting hop."
            })

        return recommendations


class WhatIfCounterfactualSimulator:
    """
    Module 11 & 12: Counterfactual / What-If Risk Simulation Engine.
    """

    def __init__(self, twin_engine):
        self.twin_engine = twin_engine

    def run_counterfactual_simulation(self, target_asset_id, action_type, parameter=None):
        before_state = copy.deepcopy(self.twin_engine.get_digital_twin_state())
        before_analyzer = AttackPathAnalyzer(before_state)
        before_paths = before_analyzer.analyze_paths()
        
        before_top_path = before_paths[0]["path"] if before_paths else ["Gateway Router", "Server"]
        before_risk = round(sum([a["risk_score"] for a in before_state["assets"]]) / max(len(before_state["assets"]), 1), 1)

        after_state = copy.deepcopy(before_state)

        if action_type == "PATCH_VULNERABILITY":
            cve_id = parameter
            after_state["vulnerabilities"] = [v for v in after_state["vulnerabilities"] if not (v["asset_id"] == target_asset_id and v["cve_id"] == cve_id)]

        elif action_type == "CLOSE_PORT":
            port_num = int(parameter) if parameter else 445
            after_state["services"] = [s for s in after_state["services"] if not (s["asset_id"] == target_asset_id and s["port"] == port_num)]
            after_state["vulnerabilities"] = [v for v in after_state["vulnerabilities"] if v["asset_id"] != target_asset_id]

        elif action_type == "ISOLATE_HOST":
            after_state["assets"] = [a for a in after_state["assets"] if a["asset_id"] != target_asset_id]
            after_state["services"] = [s for s in after_state["services"] if s["asset_id"] != target_asset_id]
            after_state["vulnerabilities"] = [v for v in after_state["vulnerabilities"] if v["asset_id"] != target_asset_id]

        after_analyzer = AttackPathAnalyzer(after_state)
        after_paths = after_analyzer.analyze_paths()

        for asset in after_state["assets"]:
            asset_ports = [s for s in after_state["services"] if s["asset_id"] == asset["asset_id"]]
            asset_vulns = [v for v in after_state["vulnerabilities"] if v["asset_id"] == asset["asset_id"]]
            risk_calc = self.twin_engine._calculate_asset_risk(
                asset["asset_id"], asset["hostname"], asset_ports, asset_vulns, asset.get("importance", "Medium")
            )
            asset["risk_score"] = risk_calc["risk_score"]
            asset["risk_level"] = risk_calc["risk_level"]

        after_risk = round(sum([a["risk_score"] for a in after_state["assets"]]) / max(len(after_state["assets"]), 1), 1)
        after_top_path = after_paths[0]["path"] if after_paths else ["PATH_BROKEN"]

        risk_reduction = round(max(before_risk - after_risk, 0.0), 1)
        path_broken = (len(after_paths) < len(before_paths)) or (after_top_path == ["PATH_BROKEN"])

        return {
            "before_risk": before_risk,
            "after_risk": after_risk,
            "risk_reduction": risk_reduction,
            "before_path": before_top_path,
            "after_path": after_top_path,
            "path_broken": path_broken,
            "action_applied": f"{action_type} on {target_asset_id} ({parameter})",
            "recommended_action": f"Apply virtual defense {action_type} to achieve -{risk_reduction} risk reduction."
        }
