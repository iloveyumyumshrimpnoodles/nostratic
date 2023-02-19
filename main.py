'''
This project is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, 
either version 3 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this code. 
If not, see <https://www.gnu.org/licenses/>. 
'''

import os, sys
import hashlib, ssl
import mimetypes, magic
import time, json, logging

from base64 import b64encode, b64decode
from typing import Any

from nostr.event import Event
from nostr.relay_manager import RelayManager
from nostr.message_type import ClientMessageType
from nostr.filter import Filter, Filters
from nostr.key import PrivateKey

max_chunk_size = 4096 # max event size

relay_manager = RelayManager()

# add your relays here
relay_manager.add_relay("ws://127.0.0.1:6969")

relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE}) # NOTE: This disables ssl certificate verification
time.sleep(1.25) # allow the connections to open

private_key = PrivateKey()
public_key = private_key.public_key

logging.basicConfig(
    format="[%(levelname)s] [%(asctime)s] (%(module)s) - %(message)s",
    datefmt="%H:%M:%S %d/%m/%y",
    level=logging.INFO
)

def help() -> None:
    """
    Displays the usage

    :returns None: Nothing
    """

    logging.error(f"Usage: python3 {sys.argv[0]} upload/download <your filename>/<sha256 digest>")
    exit()

def json_dumps(raw: Any) -> str:
    """
    Dumps @raw in a serialized JSON string

    :param raw Any: Object to dump
    :returns str: JSON serialized string

    >>> mydict = {"foo": "bar"}
    >>> json_dumps(mydict)
    {"foo":"bar"}
    """

    return json.dumps(
        raw,
        skipkeys=True,
        indent=None,
        separators=(",", ":"),
        ensure_ascii=False
    )

def upload_file(fname: str) -> dict:
    """
    Uploads @fname to the Nostr network

    :param fname str: Filename
    :returns dict[str, str or bool or list[str]]: Status, hash digest of file and Nostr Event ID's

    >>> upload_file("myfile.txt")
    {
        "status": True,
        "digest": "",
        "event-id": ["", "", ""]
    }
    """

    file_size = os.stat(fname).st_size
    b64_blob = b""

    file_digest = hashlib.sha256()
    b64_digest = hashlib.sha256()
    with open(fname, "rb") as fd:
        while 1:

            chunk = fd.read(2048)
            if not chunk:
                break

            file_digest.update(chunk)

            b64_chunk = b64encode(chunk)

            b64_digest.update(b64_chunk)
            b64_blob += b64_chunk

    logging.info(f"File size: {file_size}")
    logging.info(f"Chunk size: {max_chunk_size}")
    logging.info(f"Base64 encoded blob size: {len(b64_blob)}")
    logging.info(f"SHA256 digest of file: {file_digest.hexdigest()}")
    logging.info(f"SHA256 digest of b64 blob: {b64_digest.hexdigest()}")
    
    chunks = []
    counter = 0
    for i in range(0, len(b64_blob), max_chunk_size):
        counter += 1

        chunk = b64_blob[i:i+max_chunk_size]

        chunk_digest = hashlib.sha256(chunk).hexdigest()
        chunk_size = len(chunk)

        event = Event(
            public_key=public_key.hex(),
            content=chunk.decode(), 
            kind=7777 # for base64 encoded files or blobs
        )

        # append metadata
        # clients can search for files
        # using these tags
        event.tags.append(["type", "chunk"])

        event.tags.append(["file-digest", file_digest.hexdigest()])
        event.tags.append(["file-name", fname])
        event.tags.append(["file-size", str(file_size)])

        event.tags.append(["b64-digest", b64_digest.hexdigest()])
        event.tags.append(["b64-size", str(len(b64_blob))])

        event.tags.append(["chunk-digest", chunk_digest])
        event.tags.append(["chunk-size", str(chunk_size)])
        event.tags.append(["chunk-counter", str(counter)])

        private_key.sign_event(event)
        relay_manager.publish_event(event)

        chunks.append(
            (chunk, chunk_size, chunk_digest, event.id)
        )

        logging.info(f"Chunk '{counter}' sent")
        time.sleep(1)
    
    logging.info("All chunks sent")

    # TODO: implement manifest system for easy indexing
    """
    logging.info("Creating and publishing manifest")
    manifest = {
        "file-digest": file_digest.hexdigest(),
        "b64-digest": b64_digest.hexdigest(),
        "chunks": chunks
    }

    event = Event(
        public_key=public_key.hex(),
        content=json_dumps(manifest),
        kind=7777
    )

    event.tags.append(["type", "manifest"])

    private_key.sign_event(event)
    """
    
    return {
        "status": True,
        "digest": file_digest.hexdigest(),
        "chunks": chunks 
    }

def get_file(digest: str) -> None:
    """
    Retrieves chunks matching @digest
    This is just an example of how you could
    lookup a file, using the tag system

    :param digest str: SHA256 digest of the file you want to download
    :returns None: Nothing

    >>> get_file("09616e51d585193dfb3d1785904d6b3d682b7838ab57de89cde7df75ca2919bd")
    """

    logging.info(f"Looking for file with SHA256 digest '{digest}'")

    filter = Filter(kinds=[7777])
    filter.add_arbitrary_tag("file-digest", [digest])

    filters = Filters([filter])

    subscription_id = "get-file"
    
    request = [ClientMessageType.REQUEST, subscription_id]
    request.extend(filters.to_json_array())
    relay_manager.add_subscription(subscription_id, filters)

    relay_manager.publish_message(
        json_dumps(request)
    )

    # wait for the request to be sent
    time.sleep(1)

    b64_blob = b""
    file_buffer = b""

    filename = None
    chunks = []
    while relay_manager.message_pool.has_events():
        event_msg = relay_manager.message_pool.get_event()

        chunk = event_msg.event.content.encode()
        counter = 0
        for tag in event_msg.event.tags:

            if tag[0] == "file-name" and not filename:
                filename = tag[1]
            
            if tag[0] == "chunk-counter":
                counter = int(tag[1])

        chunks.append(
            (chunk, counter)
        )
    
    if len(chunks) <= 0:
        logging.error("File not found!")
        exit()

    logging.info(f"Decoding and constructing original file")

    # sort by counter
    chunks.sort(key=lambda val: val[1])

    b64_digest = hashlib.sha256()
    file_digest = hashlib.sha256()
    for chunk in chunks:

        try:
            b64_chunk = chunk[0]
            file_chunk = b64decode(chunk[0])

            b64_digest.update(b64_chunk)
            file_digest.update(file_chunk)

            b64_blob += b64_chunk
            file_buffer += file_chunk
        
        except Exception as e:
            logging.error(f"Failed to construct chunk '{chunk[1]}': {str(e).rstrip()}")
            continue
    
    digest = hashlib.sha256(b64_blob).hexdigest()
    logging.info(f"SHA256 digest of received base64 blob: {b64_digest.hexdigest()}")
    logging.info(f"SHA256 digest of received file: {file_digest.hexdigest()}")
    
    if not filename:

        # guess extensionfrom mime
        mime = magic.from_buffer(file_buffer, mime=True)
        ext = mimetypes.guess_extension(
            mime
        )

        if not ext:# backup
            ext = ".file"

        filename = f"{int(time.time())}{ext}"

    logging.info(f"Storing data in '{filename}'")

    with open(filename, "wb+") as fd:
        fd.write(file_buffer)

if __name__ == "__main__": 

    if len(sys.argv) == 1:
        help()
        sys.exit(1)

    if sys.argv[1] == "upload":   

        file = " ".join(sys.argv[2:])
        upload_file(file)
    
    elif sys.argv[1] == "download":

        digest = sys.argv[2]
        get_file(digest)
    
    else:

        help()
        sys.exit(1)

    relay_manager.close_connections()