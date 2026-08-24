"""
Knowledge Graph package - Module 6.

Converts existing Digital Twin / Vulnerability / Risk data (Modules
1-4) into a NetworkX graph of typed nodes and relationships. This
package does NOT perform attack-path analysis, simulation, or AI
reasoning -- it only builds and provides read-only access to the
graph foundation those future modules (7, 8, 9) will use.
"""

from backend.knowledge_graph.graph_builder import KnowledgeGraphBuilder
from backend.knowledge_graph.graph_manager import (
    KnowledgeGraphManager,
    graph_to_dict,
    graph_from_dict,
)

__all__ = [
    "KnowledgeGraphBuilder",
    "KnowledgeGraphManager",
    "graph_to_dict",
    "graph_from_dict",
]
