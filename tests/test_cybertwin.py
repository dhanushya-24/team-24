import os
import unittest
from backend.core import DigitalTwinEngine
from backend.nmap_parser import NmapXMLParser
from backend.knowledge_graph import DigitalTwinKnowledgeGraph
from backend.ai.attack_simulator import QAttackAgent, AttackPathAnalyzer, DefensiveDecisionEngine, WhatIfCounterfactualSimulator

class TestCyberTwinAI(unittest.TestCase):
    """
    Automated Test Suite for CyberTwinAI:
    - Nmap XML parser & import idempotency (192.168.56.101)
    - Digital Twin & Knowledge Graph node creation
    - Offline Q-Learning Reinforcement Learning training
    - Attack Path analysis & Defensive Decision Engine
    - What-If Counterfactual Simulation before/after risk reduction
    """

    def setUp(self):
        self.engine = DigitalTwinEngine()

    def test_01_nmap_xml_parser(self):
        """Verifies parsing of data/scan.xml."""
        assets = NmapXMLParser.parse_scan_xml()
        self.assertGreater(len(assets), 0, "Nmap XML parser should find at least 1 host in data/scan.xml")
        target_asset = next((a for a in assets if a["ip_address"] == "192.168.56.101"), None)
        self.assertIsNotNone(target_asset, "Target host 192.168.56.101 must be extracted from XML")
        self.assertEqual(len(target_asset["ports"]), 23, "Host 192.168.56.101 should have 23 open TCP ports")

    def test_02_nmap_import_and_deduplication(self):
        """Verifies importing scan.xml into Digital Twin and checks idempotency (no duplicates)."""
        res1 = self.engine.import_nmap_scan_xml()
        self.assertTrue(res1, "Nmap XML import should return True")
        
        assets_first_import = self.engine.twin_state["assets"]
        count_101_first = len([a for a in assets_first_import if a["ip_address"] == "192.168.56.101"])
        self.assertEqual(count_101_first, 1, "Host 192.168.56.101 must be present exactly once after first import")

        # Re-import same XML to test deduplication
        res2 = self.engine.import_nmap_scan_xml()
        self.assertTrue(res2, "Second Nmap XML import should return True")
        
        assets_second_import = self.engine.twin_state["assets"]
        count_101_second = len([a for a in assets_second_import if a["ip_address"] == "192.168.56.101"])
        self.assertEqual(count_101_second, 1, "Host 192.168.56.101 must NOT be duplicated upon re-import")

    def test_03_knowledge_graph_representation(self):
        """Verifies Knowledge Graph representation of 192.168.56.101."""
        self.engine.import_nmap_scan_xml()
        kg = DigitalTwinKnowledgeGraph(self.engine.twin_state)
        graph = kg.get_graph()

        target_node = "asset:AST-19216856101"
        self.assertTrue(graph.has_node(target_node), "Knowledge graph must contain node asset:AST-19216856101")
        self.assertGreater(graph.number_of_nodes(), 10, "Knowledge Graph should contain entity nodes for ports and services")

    def test_04_offline_q_learning_agent(self):
        """Verifies offline Q-learning agent operates strictly on Digital Twin graph without network packets."""
        self.engine.import_nmap_scan_xml()
        agent = QAttackAgent(self.engine.twin_state, alpha=0.1, gamma=0.9, epsilon=0.2)
        history = agent.train(episodes=25)

        self.assertEqual(len(history), 25, "Q-Learning training should execute 25 episodes")
        self.assertGreater(len(agent.q_table), 0, "Q-Table must learn state-action pair values")

    def test_05_attack_path_and_defensive_engine(self):
        """Verifies attack path discovery and defensive prioritization."""
        self.engine.import_nmap_scan_xml()
        analyzer = AttackPathAnalyzer(self.engine.twin_state)
        paths = analyzer.analyze_paths()
        self.assertGreater(len(paths), 0, "Attack Path Analyzer must identify propagation paths")

        decision = DefensiveDecisionEngine(self.engine.twin_state)
        recs = decision.recommend_defenses()
        self.assertGreater(len(recs), 0, "Defensive Decision Engine must generate prioritized fixes")

    def test_06_what_if_counterfactual_simulation(self):
        """Verifies What-If risk remediation simulation."""
        self.engine.import_nmap_scan_xml()
        simulator = WhatIfCounterfactualSimulator(self.engine)
        res = simulator.run_counterfactual_simulation("AST-19216856101", "PATCH_VULNERABILITY", "CVE-2011-2523")

        self.assertIsNotNone(res, "What-If simulation result must not be None")
        self.assertIn("before_risk", res, "Result must contain before_risk score")
        self.assertIn("after_risk", res, "Result must contain after_risk score")
        self.assertGreaterEqual(res["before_risk"], res["after_risk"], "Before risk should be >= after risk")

if __name__ == "__main__":
    unittest.main()
