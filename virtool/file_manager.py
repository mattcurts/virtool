import os
import time
import queue
import asyncio
import logging
import setproctitle
import multiprocessing
import inotify.adapters

from virtool.utils import file_stats


TYPE_NAME_DICT = {
    "IN_CREATE": "create",
    "IN_MODIFY": "modify",
    "IN_DELETE": "delete",
    "IN_MOVED_FROM": "delete",
    "IN_CLOSE_WRITE": "close"
}


class Manager:

    def __init__(self, loop, db, dispatch, path, clean_interval=20):
        self.loop = loop
        self.db = db
        self.dispatch = dispatch
        self.path = path
        self.clean_interval = clean_interval

        self.queue = multiprocessing.Queue()
        self.watcher = Watcher(self.path, self.queue)
        self.watcher.start()

        self._kill = False
        self.alive = None

    async def start(self):
        if self.clean_interval is not None:
            self.loop.create_task(self.clean())

        self.loop.create_task(self.run())
        msg = self.queue.get(block=True, timeout=3)

        assert msg == "alive"
        self.alive = True

    async def clean(self):
        looped_once = False

        while not (self._kill and looped_once):
            dir_list = os.listdir(self.path)
            db_list = await self.db.files.distinct("_id")

            for filename in dir_list:
                if filename not in db_list:
                    os.remove(os.path.join(self.path, filename))

            await self.db.files.delete_many({
                "_id": {
                    "$in": [filename for filename in db_list if filename not in dir_list]
                }
            })

            await asyncio.sleep(self.clean_interval, loop=self.loop)

            looped_once = True

    async def run(self):
        looped_once = False

        try:
            while not (self._kill and looped_once):
                while True:
                    try:
                        event = self.queue.get(block=False)

                        filename = event["file"]["filename"]

                        if event["action"] == "create":
                            await self.db.files.update_one({"_id": filename}, {
                                "$set": {
                                    "created": True
                                }
                            })

                        elif event["action"] == "modify":
                            await self.db.files.update_one({"_id": filename}, {
                                "$set": {
                                    "size_now": event["file"]["size"]
                                }
                            })

                        elif event["action"] == "close":
                            await self.db.files.update_one({"_id": filename}, {
                                "$set": {
                                    "eof": True,
                                    "size_now": event["file"]["size"]
                                }
                            })

                        elif event["action"] == "delete":
                            await self.db.files.delete_one({"_id": filename})

                    except queue.Empty:
                        break

                await asyncio.sleep(0.1, loop=self.loop)

                looped_once = True

        except KeyboardInterrupt:
            pass

        self.watcher.terminate()
        self.alive = False

        logging.debug("Stopped file watcher")

    async def wait_for_dead(self):
        while self.alive:
            await asyncio.sleep(0.1, loop=self.loop)

    async def close(self):
        self._kill = True
        await self.wait_for_dead()


class Watcher(multiprocessing.Process):

    def __init__(self, path, queue):
        super().__init__()

        self.path = path
        self.queue = queue

    def run(self):
        setproctitle.setproctitle("virtool-inotify")

        interval = 0.300

        notifier = inotify.adapters.Inotify()

        notifier.add_watch(bytes(self.path, encoding="utf-8"))

        last_modification = time.time()

        try:
            self.queue.put("alive")

            for event in notifier.event_gen():
                if event is not None:

                    _, type_names, _, filename = event

                    if filename and type_names[0] in TYPE_NAME_DICT:
                        assert len(type_names) == 1

                        action = TYPE_NAME_DICT[type_names[0]]

                        filename = filename.decode()

                        now = time.time()

                        if action in ["create", "modify", "close"]:
                            file_entry = file_stats(os.path.join(self.path, filename))
                            file_entry["filename"] = filename

                            if action == "modify" and (now - last_modification) > interval:
                                self.queue.put({
                                    "action": action,
                                    "file": file_entry
                                })

                                last_modification = now

                            else:
                                self.queue.put({
                                    "action": action,
                                    "file": file_entry
                                })

                        if action == "delete":
                            self.queue.put({
                                "action": "delete",
                                "file": {
                                    "filename": filename
                                }
                            })

        except KeyboardInterrupt:
            logging.debug("Stopped file watcher")



