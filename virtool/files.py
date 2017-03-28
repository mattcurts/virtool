import os
import queue
import logging
import multiprocessing

import virtool.utils
import virtool.database
import virtool.organize


class Collection(virtool.database.Collection):

    """
    All files being uploaded or downloaded are stored in a database collection with the time they are created. Files are
    only retained for twenty minutes before being deleted. Documents in the collection contain the following fields:

    * **file_id** - a unique id for the file; an ObjectID generated by MongoDB when the file document is first inserted
      into the collection

    * **name** - the name used to register the file; the name of the uploaded file or the name the file should take when
      downloaded

    * **content_type** - the format used in the file (eg. JSON, HTML)

    * **download** - boolean indicating whether the file is a download (False when the file is an upload)

    Watches directories by periodically calling functions registered using :meth:`.register`. Each function is
    identified by a *name* string. Changes in the file list are sent to listening connections
    (:class:`.web.SocketHandler` objects) in the list in :attr:`~.Watcher.listeners`

    :param dispatch: dispatches a message via the dispatcher.
    :type dispatch: func

    :param add_periodic_callback: takes a function and adds it to the IOLoop to be called periodically.
    :type add_periodic_callback: func

    :param add_periodic_callback: takes a function and adds it to the IOLoop to be called periodically.
    :type add_periodic_callback: func

    self.dispatch = dispatch

    #: A :class:`dict` containing lists keyed by a watcher *name*.
    self.files = dict()

    add_periodic_callback(self.run)

    """
    def __init__(self, dispatch, collections, settings, add_periodic_callback):
        super().__init__("files", dispatch, collections, settings, add_periodic_callback)


        self.path = os.path.join(self.settings.get("data_path"), "files")

        self.watcher_queue = multiprocessing.Queue()

        self.watcher = Watcher(self.path, self.watcher_queue)
        self.watcher.start()

        self.unwanted = dict()

        # Check the registered files every thirty seconds.
        add_periodic_callback(self.iterate, 300)

    @virtool.gen.coroutine
    def iterate(self, watcher_queue=None):
        """
        A coroutine that is called every 30 seconds after the :any:`Manager` object is created. Gets all of the
        managed files from the database and calls :meth:`.remove_file` on files older than 20 minutes and removes
        their database documents.

        """
        watcher_queue = watcher_queue or self.watcher_queue

        try:
            message = watcher_queue.get(block=False)
            yield self.handle_message(message)
        except queue.Empty:
            pass

    @virtool.gen.coroutine
    def handle_message(self, message):

        if message["action"] in ["create", "modify", "close"]:
            file_entry = message["file"]

            if message["action"] == "create":
                yield self.update({"_id": file_entry["filename"]}, {
                    "$set": {
                        "size_now": file_entry["size"],
                        "created": True
                    }
                })

            if message["action"] == "modify":
                yield self.update({"_id": file_entry["filename"]}, {
                    "$set": {
                        "size_now": file_entry["size"]
                    }
                })

            if message["action"] == "close":

                file_document = yield self.find_one({"_id": file_entry["filename"]})

                if file_document:
                    # Only let the file be ready if the passed size matches the actual size on disk.
                    if file_document["size_end"] == file_entry["size"]:
                        yield self.update({"_id": file_entry["filename"]}, {
                            "$set": {
                                "ready": True,
                                "size_now": file_entry["size"]
                            }
                        })

                    # Otherwise set up the file for removal. There is something malicious going on.
                    else:
                        yield self.remove({"_id": file_entry["filename"]})
                        logging.warning("Uploaded file size does not match the authorized file size")
        '''
        if message["action"] == "delete":
            to_remove = yield self.find({}, ["_id", "path"]).to_list(None)
            yield self.remove_files(to_remove)
        '''

    @virtool.gen.exposed_method([])
    def authorize_upload(self, transaction):
        target = yield self.collections["files"].register(
            name=transaction.data["name"],
            size=transaction.data["size"],
            file_type="hmm"
        )

        return True, dict(target=target)

    @virtool.gen.coroutine
    def register(self, name, size, file_type=None, download=False, time_getter=virtool.utils.timestamp, expires=1200):
        """
        Registers a file in the file manager. A unique ``file_id`` is generated for the file. Using :meth:`.write_file`
        , the data in the ``content`` parameter is written to a file of name ``file_id`` in the appropriate download or
        upload directory. The passed ``name`` and ``content_type`` are stored in the database.

        :param name: the name of an uploaded file or the name for the file should it be downloaded.
        :type name: str

        :param size: the size of the file in bytes
        :type size: int

        :param file_type: the type of file (reads, host_fasta, upload, download)
        :type file_type: str

        :param download: the file should be available at '/download/<file_id>'
        :type download: bool

        :param time_getter: a datetime object to attach to the database document.
        :type time_getter: func

        :param expires: the number of seconds the file should be kept before it is automatically deleted
        :type expires: int

        :return: a unique file id.
        :rtype: str

        """
        target = yield self.get_new_id()

        yield self.insert({
            "_id": "{}-{}".format(target, name),
            "name": name,
            "target": target,
            "ready": False,
            "created": False,
            "size_end": size,
            "size_now": size,
            "bytes": file_type,
            "file_type": file_type,
            "download": download,
            "reserved": False,
            "timestamp": time_getter(),
            "expires": 1200
        })

        return target

    @virtool.gen.coroutine
    def reserve_files(self, file_ids, reserved=True):
        yield self.update({"_id": {"$in": file_ids}}, {
            "$set": {
                "reserved": reserved
            }
        })

    @virtool.gen.coroutine
    def reserve_files_cop(self, data):
        if "reserved" not in data:
            data["reserved"] = True

        yield self.reserve_files(data["file_ids"], data["reserved"])

    @virtool.gen.exposed_method([])
    def remove_file(self, transaction):
        """
        Removes a file from the database collection and from the appropriate directory.

        """
        response = yield self.remove_files(transaction.data["file_id"])
        return True, response

    @virtool.gen.coroutine
    def _remove_files(self, data):
        yield self.remove_files(data["to_remove"])

    @virtool.gen.coroutine
    def remove_files(self, to_remove):
        """
        Removes a file from the database collection and from the appropriate directory.

        """
        to_remove = virtool.database.coerce_list(to_remove)

        for file_id in to_remove:
            try:
                yield virtool.utils.rm(os.path.join(self.path, file_id))
            except FileNotFoundError:
                pass

        response = yield self.remove(to_remove)

        return response



