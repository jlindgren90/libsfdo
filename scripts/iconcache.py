#!/usr/bin/env python3

import sys

from collections import defaultdict

END = 0xFFFFFFFF


def icon_hash(s):
    h = 0
    for c in s:
        h = (h << 5) - h + ord(c)
    return h


class Hole:
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size


class Cache:
    def __init__(self):
        self.data = []

    def alloc(self, size):
        addr = len(self.data)
        data = [0x5A] * size
        self.data.extend(data)
        return Hole(addr, size)

    def alloc16(self):
        return self.alloc(2)

    def alloc32(self):
        return self.alloc(4)

    def write(self, hole, n):
        # Big-endian
        for i in range(hole.size):
            self.data[hole.addr + hole.size - i - 1] = (n >> (8 * i)) & 0xFF

    def push16(self, n):
        self.write(self.alloc16(), n)

    def push32(self, n):
        self.write(self.alloc32(), n)

    def push_strings(self, str_dict):
        for s, hole in str_dict.items():
            self.write(hole, self.curr())
            self.data.extend(s.encode() + b"\0")

    def curr(self):
        return len(self.data)


def main():
    dir_map = dict()
    icon_map = defaultdict(lambda: defaultdict(set))

    icons_path = sys.argv[1]
    for line in open(icons_path).readlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        s, _, file_name = line.rpartition("/")
        name, ext = file_name.split(".")
        dir_i = dir_map.get(s, len(dir_map))
        dir_map[s] = dir_i
        icon_map[name][dir_i].add(ext)

    cache = Cache()

    # MAJOR_VERSION
    cache.push16(1)
    # MINOR_VERSION
    cache.push16(0)

    # HASH_OFFSET
    hash_off_hole = cache.alloc32()
    # DIRECTORY_LIST_OFFSET
    dir_list_off_hole = cache.alloc32()

    cache.write(dir_list_off_hole, cache.curr())
    # N_DIRECTORIES
    cache.push32(len(dir_map))

    dir_holes = dict()
    for dir in dir_map.keys():
        # DIRECTORY_OFFSET
        dir_holes[dir] = cache.alloc32()

    cache.push_strings(dir_holes)

    buckets = [[] for _ in range(31)]

    for name in icon_map.keys():
        h = icon_hash(name)
        b = buckets[h % len(buckets)]
        b.append(name)

    cache.write(hash_off_hole, cache.curr())
    # N_BUCKETS
    cache.push32(len(buckets))

    bucket_holes = []
    for _ in range(len(buckets)):
        # ICON_OFFSET
        bucket_holes.append(cache.alloc32())

    name_holes = dict()
    list_holes = dict()
    for i, b in enumerate(buckets):
        hole = bucket_holes[i]
        for name in b:
            cache.write(hole, cache.curr())
            # CHAIN_OFFSET
            hole = cache.alloc32()
            # NAME_OFFSET
            name_holes[name] = cache.alloc32()
            # IMAGE_LIST_OFFSET
            list_holes[name] = cache.alloc32()
        cache.write(hole, END)

    cache.push_strings(name_holes)

    for name, dirs in icon_map.items():
        hole = list_holes[name]
        cache.write(hole, cache.curr())
        # N_IMAGES
        cache.push32(len(dirs))
        for dir_i, exts in dirs.items():
            flags = 0
            if "xpm" in exts:
                flags |= 1
            if "svg" in exts:
                flags |= 2
            if "png" in exts:
                flags |= 4
            # DIRECTORY_INDEX
            cache.push16(dir_i)
            # FLAGS
            cache.push16(flags)
            # IMAGE_DATA_OFFSET
            cache.push32(END)

    cache_path = sys.argv[2]
    cache_file = open(cache_path, "wb")
    cache_file.write(bytes(cache.data))


main()
