from typing import Any
import socket
import struct
import traceback
import threading
import time
import os
import functools
from collections import OrderedDict
import base64
import json
import niquests as requests
from hashlib import sha256
from cryptography.fernet import Fernet
from meshtastic.protobuf import mesh_pb2
mesh_pb2.MeshPacket

multicast_group = '224.0.0.69'

defaultpsk = b"\xd4\xf1\xbb\x3a\x20\x29\x07\x59\xf0\xbc\xff\xab\xcf\x4e\x69\x01"

# Assume 100 users with 12 devices each sending every minute
# Probably like 500MB of ram for all this but whatever
recently_seen_limit = 60* 60 * 100 * 12 

# Track packets we have seen and when we have seen them.
# We don't want to let any replay attacks through.
recentlySeen: OrderedDict[int, float] = OrderedDict()


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Construct the membership request
group = socket.inet_aton(multicast_group)
mreq = struct.pack('4s4s', group, socket.inet_aton("0.0.0.0"))

# Set the socket option to join the multicast group
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# timeout
sock.settimeout(5)

sock.bind(('', 4403))


@functools.cache
def cached_sha256(d: bytes):
    return sha256(d).digest()

def bytes_to_dhtkey(d: bytes):
    h = d.hex()
    hash = ('0'*(40-len(h))) + h
    return hash

def publish_to_dht(rawdata: bytes, key: bytes):

    # print("publishing to dht", rawdata, key)
    # return
    d: dict[str, int | str] = {
            "data": base64.b64encode(rawdata).decode(),
            "id": str(os.urandom(12)),
            "seq": 0,
            "type": 3,
        }

    hexkey = bytes_to_dhtkey(key)
    print("publishing to dht", hexkey, d)
    requests.post(
        f"http://dhtproxy.jami.net/key/{hexkey}", json=d
    ).raise_for_status() #type: ignore

def decode_from_dht(data: str):
    return base64.b64decode(json.loads(data)["data"])

def markSeen(encrypted_packet: bytes):
    if len(recentlySeen) >= (recently_seen_limit/2):
        while 1:
            oldest = list(recentlySeen.keys())[0]
            if recentlySeen[oldest] < time.time() - 60 * 80:
                recentlySeen.pop(oldest)
            else:
                break
    
    if len(recentlySeen) >= recently_seen_limit:
        return
    
    hash = cached_sha256(encrypted_packet)[:8]
    asnumber = struct.unpack("<Q", hash)[0]
    recentlySeen[asnumber] = time.time()


def isRecentlySeen(encrypted_packet: bytes):
    # If the list is getting full just assume absolutely everything is
    # a replay.
    if len(recentlySeen) >= recently_seen_limit-100:
        return True
    
    hash = cached_sha256(encrypted_packet)[:8]
    asnumber = struct.unpack("<Q", hash)[0]
    if asnumber in recentlySeen:
        if recentlySeen[asnumber] > time.time() - 60 * 80:
            return True
    return False


def get_key(b64_key: str):
    key = base64.b64decode(b64_key)
   # They do a key stretching thing that makes exactly no sense to me
    if(len(key)==1):
        key2 = bytearray(defaultpsk)
        key2[-1] +=  (key[0]-1)
        key = bytes(key2)

    # pad to 32 bytes
    if len(key) < 32:
        key += b'\x00' * (32 - len(key))
    return key

def hashchannel(name: str, key: bytes):

 
    
    print(name, key)
    xorstate = 0
    xorstate2 = 0
    for i in name.encode():
        xorstate ^= i
    for i in key:
        xorstate2 ^= i

    res= xorstate ^ xorstate2
    return res



class ChannelMappingListener:
    def __init__(
        self,
        temp_group_key: bytes,
    ):
        self.temp_group_key = temp_group_key

        fernet = Fernet(base64.b64encode(temp_group_key))
        
        temp_dht_key = bytes_to_dhtkey(sha256(temp_group_key).digest()[:20])

        url = f"http://dhtproxy.jami.net/key/{temp_dht_key}/listen"

        # streaming JSON lines connection in a thread
        self.conn: None | requests.models.Response = None


        self.last_interest = time.time()

        def listener_thread():
            while self.last_interest > time.time() - 15 * 60:
                self.conn = requests.get(url, stream=True, timeout=3600)#type: ignore
                print("dht thread key "+url)
                try:
                    for i in self.conn.iter_lines(delimiter=b"\n"):
                        if i:
                            print("Packet from DHT:", i)
                            try:

                                data = decode_from_dht(i.decode())
                                data = fernet.decrypt(data)

                                self.on_packet(
                                    data.decode()
                                )
                            except Exception:
                                print(traceback.format_exc())
                except Exception:
                    print(traceback.format_exc())
            self.conn = None

        self.thread = threading.Thread(target=listener_thread, daemon=True)
        self.thread.start()

    def on_packet(self, packet: str):
        j = json.loads(packet)

        udp_packet = base64.b64decode(j["radio"])
        decoded_packet = mesh_pb2.MeshPacket.FromString(udp_packet)

        if isRecentlySeen(decoded_packet.encrypted):
            print("already seen this incoming DHT packet")
            return
        markSeen(decoded_packet.encrypted)

        if decoded_packet.hop_limit == 0:
            return

        decoded_packet.hop_limit -= 1

        sock.sendto(decoded_packet.SerializeToString(), ("237.84.2.178", 1783))
        

    def close(self):
        if self.conn:
            self.conn.close()
        self.thread.join()


active_listeners: list[ChannelMappingListener] = []


class OutgoingMapping():
    """Only valid temporarliy, needs remade periodically as temp group key expires"""
    def __init__(self, channel_hash: int, sender_id: int|None, temp_group_key: bytes):
        print("createMapping", channel_hash, sender_id, temp_group_key)
        self.channel_hash = channel_hash
        self.sender_id = sender_id
        self.timestamp = time.time()
        self.temp_group_key = temp_group_key

        self.temp_dht_key = sha256(temp_group_key).digest()[:20]

        self.fernet = Fernet(base64.b64encode(self.temp_group_key))
    
    def encrypt(self, packet: bytes):
        return self.fernet.encrypt(packet)

OutgoingMappings: list[OutgoingMapping] =[]

PermanentMappings=[
    ('test', "BQ=="),
   # ("LongFast", "AQ==")
]

def cleanOldOutgoingMappings():
    torm: list[OutgoingMapping] = []
    for m in OutgoingMappings:
        if time.time() - m.timestamp > 60 * 15:
            torm.append(m)

    for m in torm:
        OutgoingMappings.remove(m)

    torm2: list[ChannelMappingListener] = []
    for m in active_listeners:
        if time.time() - m.last_interest > 60 * 15:
            torm2.append(m)

    for m in torm2:
        # We just lead the thread end itself
        active_listeners.remove(m)


def createMapping(channel_hash: int, sender_id: int|None, temp_group_key: bytes):
    found_listener = False
    for i in active_listeners:
        if i.temp_group_key == temp_group_key:
            i.last_interest = time.time()
            found_listener = True
            break

    if not found_listener:
        c = ChannelMappingListener(temp_group_key)
        active_listeners.append(c)

    for i in OutgoingMappings:
        if i.channel_hash == channel_hash:
            if i.sender_id == sender_id:
                return

    OutgoingMappings.append(OutgoingMapping(channel_hash, sender_id, temp_group_key))

def createNeededMappings():
    # Only call once per ten minutes

    timeblock = int(time.time() / 3600)

    for i in PermanentMappings:
        key  = get_key(i[1])
        #key = i[1].encode()
        temp_group_key = sha256(timeblock.to_bytes(4, 'little')+key).digest()

        channelhash = hashchannel(i[0], key )
        createMapping(channelhash, None,temp_group_key)

def multicastlistener():


    lastMaintainece = 0


    while True:
        if time.time() - lastMaintainece > 10*60:
            cleanOldOutgoingMappings()
            createNeededMappings()
            lastMaintainece = time.time()
        try:  
            data, _addr = sock.recvfrom(1024)
            x = mesh_pb2.MeshPacket.FromString(data)

            if isRecentlySeen(x.encrypted):
                print("already seen this radio packet")
                continue

            markSeen(x.encrypted)

            # TODO ideally the mesh node sends something to opt-in to this.
            for i in OutgoingMappings:
                print("mapping", i.channel_hash, i.sender_id)
                if i.channel_hash == x.channel:
                    if i.sender_id == x.__getattribute__("from") or i.sender_id is None:
                        dht_data_raw = {
                            "radio": base64.b64encode(data).decode(),
                        }

                        dht_data = i.encrypt(json.dumps(dht_data_raw).encode())

                        publish_to_dht(dht_data, i.temp_dht_key)

            print("received message:", data, x)
        except socket.timeout:
            pass

multicastlistener()