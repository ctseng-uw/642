import hashlib
import multiprocessing
from multiprocessing import Queue, Pool
import os
import signal

total = 63941069
salt = "9578721033"

NPROCESS = multiprocessing.cpu_count()
TARGET = "80cb3696e6fe9953e61048ad0013e4e9d31e26d0b10eec5650b26625033dfbe4203f1cc793e2df9031e96a1a877cce2f5da4cc8ec0698c382438aae4591a5d1a"
USERNAME = "bucky"


def crypt(q: Queue, ppid: int):
    while True:
        message = q.get()
        message = USERNAME + "," + message
        if message is None:
            break
        h = hashlib.scrypt(password=message.encode(),
                           salt=salt.encode(),
                           n=16,
                           r=32,
                           p=1)
        if h.hex() == TARGET:
            print(message)
            os.kill(ppid, signal.SIGTERM)


def gen():
    with open("crackstation-human-only.txt", "r", encoding="latin1") as f:
        cnt = 0
        for line in f:
            cnt += 1
            if cnt % 100000 == 0:
                print(f"{cnt / total * 100:.2f}%", end="\r")
            line = line.split("\n")[0]
            if len(line) < 6:
                continue
            up, lo, sy, di = 0, 0, 0, 0
            for c in line:
                if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    up = 1
                elif c in "abcdefghijklmnopqrstuvwxyz":
                    lo = 1
                elif c in "~`!@#$%^&*()+=_-\{\}[]\|:;”’?/<>,.":
                    sy = 1
                elif c in "0123456789":
                    di = 1
                if up + lo + sy + di >= 3:
                    break
            else:
                continue
            yield line


def main():
    q = Queue(maxsize=NPROCESS * 2)
    with Pool(NPROCESS, initializer=crypt, initargs=(q, os.getpid())):
        for string in gen():
            q.put(string)


if __name__ == "__main__":
    main()
