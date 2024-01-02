"""
Core database classes.


"""
from contextlib import asynccontextmanager
from typing import Any, Awaitable, Callable

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorClientSession
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

import virtool.analyses.db
import virtool.caches.db
import virtool.history.db
import virtool.hmm.db
import virtool.indexes.db
import virtool.mongo.utils
import virtool.otus.db
import virtool.references.db
import virtool.samples.db
import virtool.subtractions.db
import virtool.uploads.db
import virtool.users.db
import virtool.utils
from virtool.mongo.identifier import AbstractIdProvider
from virtool.mongo.utils import id_exists
from virtool.types import Document, Projection


class Collection:
    """
    A wrapper for a Motor collection.

    Wraps collection methods that modify the database and automatically dispatches
    websocket messages to inform clients of the changes.

    """

    def __init__(
        self,
        mongo: "Mongo",
        name: str,
        processor: Callable[[Any, Document], Awaitable[Document]],
        projection: Projection | None,
    ):
        self.mongo = mongo
        self.name = name
        self._collection = mongo.motor_client[name]
        self.processor = processor
        self.projection = projection

        self.aggregate = self._collection.aggregate
        self.bulk_write = self._collection.bulk_write
        self.count_documents = self._collection.count_documents
        self.create_index = self._collection.create_index
        self.delete_many = self._collection.delete_many
        self.delete_one = self._collection.delete_one
        self.distinct = self._collection.distinct
        self.drop_index = self._collection.drop_index
        self.drop_indexes = self._collection.drop_indexes
        self.find_one = self._collection.find_one
        self.find = self._collection.find
        self.rename = self._collection.rename
        self.replace_one = self._collection.replace_one
        self.update_many = self._collection.update_many
        self.update_one = self._collection.update_one

    async def apply_processor(self, document):
        if self.processor:
            return await self.processor(self.mongo, document)

        return virtool.utils.base_processor(document)

    async def find_one_and_update(
        self,
        query: dict,
        update: dict,
        projection: Projection | None = None,
        upsert: bool = False,
        session: AsyncIOMotorClientSession | None = None,
    ) -> Document | None:
        """
        Update a document and return the updated result.

        :param query: a MongoDB query used to select the documents to update
        :param update: a MongoDB update
        :param projection: a projection to apply to the document instead of the default
        :param upsert: insert a new document if no existing document is found
        :param session: an optional Motor session to use
        :return: the updated document

        """
        document = await self._collection.find_one_and_update(
            query,
            update,
            return_document=ReturnDocument.AFTER,
            upsert=upsert,
            session=session,
        )

        if document is None:
            return None

        if projection:
            return virtool.mongo.utils.apply_projection(document, projection)

        return document

    async def insert_one(
        self, document: Document, session: AsyncIOMotorClientSession | None = None
    ) -> Document:
        """
        Insert the `document`.

        If no `_id` is included in the `document`, one will be autogenerated. If a
        provided `_id` already exists, a :class:`DuplicateKeyError` will be raised.

        :param document: the document to insert
        :param session: an optional Motor session to use
        :return: the inserted document

        """
        if "_id" in document:
            await self._collection.insert_one(document, session=session)
            inserted = document
        else:
            document_id = self.mongo.id_provider.get()

            if await id_exists(self, document_id, session):
                inserted = await self.insert_one(document, session=session)
            else:
                inserted = {**document, "_id": document_id}
                await self._collection.insert_one(inserted, session=session)

        return inserted

    async def insert_many(
        self, documents: list[Document], session: AsyncIOMotorClientSession
    ):
        inserted = await self.populate_bulk_ids(documents, session=session)

        await self._collection.insert_many(inserted, session=session)

        return inserted

    async def populate_bulk_ids(
        self, documents: list[Document], session: AsyncIOMotorClientSession = None
    ):
        is_id_populated = any("_id" in document for document in documents)

        id_documents = [
            {**document, "_id": document["_id"] or self.mongo.id_provider.get()}
            for document in documents
        ]

        if await self.find_one(
            {"_id": {"in": [document["_id"] for document in id_documents]}},
            session=session,
        ):
            if is_id_populated:
                raise DuplicateKeyError
            await self.populate_bulk_ids(documents)

        return id_documents


class Mongo:
    def __init__(
        self, motor_client: AsyncIOMotorClient, id_provider: AbstractIdProvider
    ):
        self.motor_client = motor_client
        self.start_session = motor_client.start_session
        self.id_provider = id_provider

        self.analyses = self.bind_collection(
            "analyses", projection=virtool.analyses.db.PROJECTION
        )

        self.caches = self.bind_collection(
            "caches", projection=virtool.caches.db.PROJECTION
        )

        self.files = self.bind_collection(
            "files", projection=virtool.uploads.db.PROJECTION
        )

        self.groups = self.bind_collection("groups")

        self.history = self.bind_collection(
            "history", projection=virtool.history.db.PROJECTION
        )

        self.hmm = self.bind_collection("hmm", projection=virtool.hmm.db.PROJECTION)

        self.indexes = self.bind_collection(
            "indexes", projection=virtool.indexes.db.INDEXES_PROJECTION
        )

        self.jobs = self.bind_collection(
            "jobs",
            projection=(
                "_id",
                "archived",
                "workflow",
                "status",
                "rights",
                "user",
            ),
        )

        self.keys = self.bind_collection("keys")

        self.labels = self.bind_collection("labels")

        self.migrations = self.bind_collection("migrations")

        self.otus = self.bind_collection("otus", projection=virtool.otus.db.PROJECTION)

        self.tasks = self.bind_collection("tasks")

        self.references = self.bind_collection(
            "references",
            processor=virtool.references.db.processor,
            projection=virtool.references.db.PROJECTION,
        )

        self.samples = self.bind_collection(
            "samples", projection=virtool.samples.db.LIST_PROJECTION
        )
        self.settings = self.bind_collection("settings", projection={"_id": False})

        self.sequences = self.bind_collection("sequences")

        self.sessions = self.bind_collection("sessions")

        self.status = self.bind_collection("status")

        self.subtraction = self.bind_collection(
            "subtraction", projection=virtool.subtractions.db.PROJECTION
        )

        self.users = self.bind_collection(
            "users", projection=virtool.users.db.PROJECTION
        )

    def bind_collection(
        self,
        name: str,
        processor: Callable | None = None,
        projection: Projection | None = None,
    ) -> Collection:
        return Collection(self, name, processor, projection)

    @asynccontextmanager
    async def create_session(self):
        async with await (
            self.motor_client.client.start_session()
        ) as s, s.start_transaction():
            yield s

    @asynccontextmanager
    async def with_session(self):
        async with await self.motor_client.client.start_session() as s:
            yield s

    async def with_transaction(self, function: Callable):
        async with await self.motor_client.client.start_session() as s:
            await s.with_transaction(function)
