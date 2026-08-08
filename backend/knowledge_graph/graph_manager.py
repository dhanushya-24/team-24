"""
graph_manager.py
=================
RESPONSIBILITY: Manage the CURRENT Knowledge Graph's lifecycle --
build it from the Digital Twin, persist it, load it back, and clear
it. This file contains NO graph construction logic itself (that
lives in graph_builder.py) and NO query logic (that lives in
graph_queries.py) -- it only orchestrates.

Persistence reuses the existing backend.database.mongodb.MongoDBHandler
(no second, unrelated MongoDB setup is introduced) and stores the
graph in a dedicated `knowledge_graph` collection as a single
serializable document: {"_id": "current", "nodes": [...], "edges": [...]}.
Raw NetworkX objects are never stored directly -- graph_to_dict()/
graph_from_dict() below convert to and from plain, JSON-safe data.
"""

from typing import Any, Dict, List, Optional

import networkx as nx

from backend.database.mongodb import MongoDBHandler
from backend.twin.twin_manager import TwinManager
from backend.knowledge_graph.graph_builder import KnowledgeGraphBuilder, AssetLike

# The single MongoDB document that always holds the CURRENT graph.
# Using one fixed ID keeps this simple (a student prototype doesn't
# need graph history/versioning yet -- that would be a natural future
# enhancement, not required for Module 6).
GRAPH_DOCUMENT_ID = "current"
KNOWLEDGE_GRAPH_COLLECTION = "knowledge_graph"


def graph_to_dict(graph: nx.DiGraph) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convert a NetworkX graph into a plain, JSON-serializable dict:
        {"nodes": [{"id": ..., <attributes>}, ...],
         "edges": [{"source": ..., "target": ..., <attributes>}, ...]}

    This is the ONLY format ever written to MongoDB or returned by
    the Flask API for the graph -- never a raw NetworkX object.
    """
    nodes = [{"id": node_id, **attributes} for node_id, attributes in graph.nodes(data=True)]
    edges = [
        {"source": source, "target": target, **attributes}
        for source, target, attributes in graph.edges(data=True)
    ]
    return {"nodes": nodes, "edges": edges}


def graph_from_dict(data: Dict[str, List[Dict[str, Any]]]) -> nx.DiGraph:
    """
    Rebuild a NetworkX DiGraph from the plain dict format produced by
    graph_to_dict() (e.g. after loading it back from MongoDB or from
    the Flask API's /knowledge-graph response).
    """
    graph = nx.DiGraph()

    for node in data.get("nodes", []):
        node = dict(node)  # don't mutate the caller's data
        node_id = node.pop("id")
        graph.add_node(node_id, **node)

    for edge in data.get("edges", []):
        edge = dict(edge)
        source = edge.pop("source")
        target = edge.pop("target")
        graph.add_edge(source, target, **edge)

    return graph


class KnowledgeGraphManager:
    """
    Owns the Knowledge Graph's lifecycle for a running application:
    build it from the current Digital Twin state, save/load it via
    MongoDB, and hand back the in-memory NetworkX graph on request.
    """

    def __init__(
        self,
        db_handler: Optional[MongoDBHandler] = None,
        twin_manager: Optional[TwinManager] = None,
    ) -> None:
        # Reuse the SAME MongoDBHandler class as the rest of the
        # project (no second database architecture).
        self.db = db_handler or MongoDBHandler()
        self.twin_manager = twin_manager or TwinManager(self.db)
        self._graph: Optional[nx.DiGraph] = None

    # ------------------------------------------------------------------
    def build_graph(
        self,
        assets: Optional[List[AssetLike]] = None,
        connections: Optional[List[Dict[str, Any]]] = None,
    ) -> nx.DiGraph:
        """
        Build the Knowledge Graph.

        Args:
            assets: list of Asset objects/dicts to build from. If
                None, the CURRENT Digital Twin state is loaded via
                TwinManager.load_all_assets() -- this is the normal
                usage (Module 6 consumes Modules 1-4's existing work,
                it does not redo any of it).
            connections: optional real connection records (see
                graph_builder.KnowledgeGraphBuilder.build_from_assets()).

        Returns:
            The newly-built NetworkX graph (also cached on this
            manager instance, accessible via get_graph()).
        """
        if assets is None:
            assets = self.twin_manager.load_all_assets()

        builder = KnowledgeGraphBuilder()
        self._graph = builder.build_from_assets(assets, connections=connections)
        return self._graph

    def get_graph(self) -> nx.DiGraph:
        """Return the current in-memory graph, building it first if needed."""
        if self._graph is None:
            self.build_graph()
        return self._graph

    # ------------------------------------------------------------------
    def save_graph(self) -> None:
        """
        Persist the current in-memory graph into MongoDB as a plain,
        serializable document (never a raw NetworkX object).

        Raises:
            ValueError: if no graph has been built yet.
        """
        if self._graph is None:
            raise ValueError("No graph has been built yet -- call build_graph() first.")

        document = {"_id": GRAPH_DOCUMENT_ID, **graph_to_dict(self._graph)}
        self.db.upsert_one(
            KNOWLEDGE_GRAPH_COLLECTION,
            {"_id": GRAPH_DOCUMENT_ID},
            document,
        )

    def load_graph(self) -> Optional[nx.DiGraph]:
        """
        Load a previously-saved graph from MongoDB.

        Returns:
            The loaded NetworkX graph, or None if nothing has been
            saved yet. On success, this also becomes the manager's
            current in-memory graph (get_graph() will return it).
        """
        document = self.db.find_one(KNOWLEDGE_GRAPH_COLLECTION, {"_id": GRAPH_DOCUMENT_ID})
        if document is None:
            return None

        self._graph = graph_from_dict(document)
        return self._graph

    def clear_graph(self) -> None:
        """Discard the in-memory graph and delete any saved copy in MongoDB."""
        self._graph = None
        self.db.delete_one(KNOWLEDGE_GRAPH_COLLECTION, {"_id": GRAPH_DOCUMENT_ID})
