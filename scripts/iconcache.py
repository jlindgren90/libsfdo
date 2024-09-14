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

    def alloc_s(self, s):
        return self.alloc(len(s) + 1)

    def write(self, hole, n):
        # Big-endian
        for i in range(hole.size):
            self.data[hole.addr + hole.size - i - 1] = (n >> (8 * i)) & 0xFF

    def write_s(self, hole, s):
        b = s.encode() + b"\0"
        for i in range(hole.size):
            self.data[hole.addr + i] = b[i]

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
    cache.write(cache.alloc(2), 1)
    # MINOR_VERSION
    cache.write(cache.alloc(2), 0)

    # HASH_OFFSET
    hash_off_hole = cache.alloc(4)
    # DIRECTORY_LIST_OFFSET
    dir_list_off_hole = cache.alloc(4)

    cache.write(dir_list_off_hole, cache.curr())
    # N_DIRECTORIES
    cache.write(cache.alloc(4), len(dir_map))

    dir_holes = [None for _ in range(len(dir_map))]
    for dir, i in dir_map.items():
        # DIRECTORY_OFFSET
        dir_holes[i] = (cache.alloc(4), dir)

    for hole, dir in dir_holes:
        cache.write(hole, cache.curr())
        cache.write_s(cache.alloc_s(dir), dir)

    buckets = [[] for _ in range(31)]

    for name in icon_map.keys():
        h = icon_hash(name)
        b = buckets[h % len(buckets)]
        b.append(name)

    cache.write(hash_off_hole, cache.curr())
    # N_BUCKETS
    cache.write(cache.alloc(4), len(buckets))

    bucket_holes = []
    for _ in range(len(buckets)):
        # ICON_OFFSET
        bucket_holes.append(cache.alloc(4))

    name_holes = dict()
    list_holes = dict()
    for i, b in enumerate(buckets):
        hole = bucket_holes[i]
        for line in b:
            cache.write(hole, cache.curr())
            # CHAIN_OFFSET
            hole = cache.alloc(4)
            # NAME_OFFSET
            name_holes[line] = cache.alloc(4)
            # IMAGE_LIST_OFFSET
            list_holes[line] = cache.alloc(4)
        cache.write(hole, END)

    for line in icon_map.keys():
        cache.write(name_holes[line], cache.curr())
        cache.write_s(cache.alloc_s(line), line)

    for line, dirs in icon_map.items():
        hole = list_holes[line]
        cache.write(hole, cache.curr())
        # N_IMAGES
        cache.write(cache.alloc(4), len(dirs))
        for dir_i, exts in dirs.items():
            flags = 0
            if "xpm" in exts:
                flags |= 1
            if "svg" in exts:
                flags |= 2
            if "png" in exts:
                flags |= 4
            # DIRECTORY_INDEX
            cache.write(cache.alloc(2), dir_i)
            # FLAGS
            cache.write(cache.alloc(2), flags)
            # IMAGE_DATA_OFFSET
            cache.write(cache.alloc(4), END)

    cache_path = sys.argv[2]
    cache_file = open(cache_path, "wb")
    cache_file.write(bytes(cache.data))


main()
