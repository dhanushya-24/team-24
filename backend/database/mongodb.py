"""
mongodb.py
==========
The ONLY file in the entire project allowed to talk to MongoDB directly.

Every other module (discovery/database.py, twin/twin_manager.py, and
later modules) must go through the MongoDBHandler class defined here.

Why centralize this?
    If you ever need to change the connection string, add
    authentication, switch to MongoDB Atlas, or add logging around
    every query -- you change ONE file, not five.
"""

from typing import Optional
from pymongo import MongoClient
from pymongo.collection import Collection


class MongoDBHandler:
    """
    Thin wrapper around pymongo that exposes only the operations this
    project actually needs: connect, insert, update (upsert), delete,
    find one, find many.

    Kept deliberately generic (collection name is a parameter) so the
    same class serves 'assets', 'services', 'connections', and
    'vulnerabilities' collections without duplicating code.
    """

    def __init__(self, uri: str = "mongodb://localhost:27017/", db_name: str = "cybertwin"):
        # A single client connection is created and reused for the
        # lifetime of this object (this is the recommended pymongo
        # pattern -- do NOT create a new MongoClient per query).
        self.client = MongoClient(uri)
        self.db = self.client[db_name]

    def get_collection(self, collection_name: str) -> Collection:
        """Return a pymongo Collection object by name."""
        return self.db[collection_name]

    # ------------------------------------------------------------------
    def insert_one(self, collection_name: str, document: dict):
        """Insert a single new document. Returns the inserted document's _id."""
        collection = self.get_collection(collection_name)
        result = collection.insert_one(document)
        return result.inserted_id

    # ------------------------------------------------------------------
    def upsert_one(self, collection_name: str, query: dict, document: dict):
        """
        Update a document matching `query` if it exists, otherwise
        insert it as new. This is the operation used almost everywhere
        in this project (discovery re-scans the same devices, the twin
        re-syncs the same assets), because it makes "save" idempotent:
        running the same scan twice does not create duplicates.
        """
        collection = self.get_collection(collection_name)
        result = collection.update_one(query, {"$set": document}, upsert=True)
        return result

    # ------------------------------------------------------------------
    def delete_one(self, collection_name: str, query: dict):
        """Delete a single document matching `query`. Used rarely and
        only when explicitly requested (see twin_manager.py notes on
        why assets are NOT auto-deleted)."""
        collection = self.get_collection(collection_name)
        result = collection.delete_one(query)
        return result.deleted_count

    # ------------------------------------------------------------------
    def find_one(self, collection_name: str, query: dict) -> Optional[dict]:
        collection = self.get_collection(collection_name)
        return collection.find_one(query)

    # ------------------------------------------------------------------
    def find_many(self, collection_name: str, query: Optional[dict] = None) -> list:
        collection = self.get_collection(collection_name)
        query = query or {}
        return list(collection.find(query))

    # ------------------------------------------------------------------
    def close(self):
        """Close the MongoDB connection cleanly when the app shuts down."""
        self.client.close()
