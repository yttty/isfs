#! /bin/python3
import os
import sys


def make_big_file(size, dirname, fname):
    content = 'A' * size
    with open('/mnt/test_file', 'w+') as f:
        f.write(content)
    cmd = f'cp /mnt/test_file {dirname}/{fname}'
    os.system(cmd)
    with open(f"{dirname}/{fname}") as f:
        c = f.read(size)
        if (c == content):
            print('[PASS]')
        else:
            print('[FAIL]')


def test_big_file():
    os.chdir(sys.argv[1])
    dname = "bigfile"
    os.system(f"mkdir -p {dname}")

    print('[TEST] small-file, using 1 direct data block')
    make_big_file(500, dname, 'file1')  # one block
    print('[TEST] small-file, using 2 direct data blocks')
    make_big_file(1000, dname, 'file2')  # two block
    print('[TEST] big-file, using indirect data blocks')
    make_big_file(128 * 512, dname, 'file3')  # indirect block
    print('[TEST] bigger-file, using double direct data blocks')
    make_big_file(256 * 512, dname, 'file4')  # double indirect block
    print(
        '[TEST] biggest-file, using maximum number of data blocks (takes a lot of time...)'
    )
    make_big_file((128 * 128 + 128 + 2) * 512 - 10, dname, 'file5')


def make_dir(size, pdname, dirname):
    os.system(f'mkdir -p {pdname}/{dirname}')
    content = "I am big!"
    for i in range(size):
        cmd = f'''echo \"{content}\" >> {pdname}/{dirname}/{'f'+str(i)}'''
        os.system(cmd)
    files = os.listdir(f'{pdname}/{dirname}')
    if (files == [f'f{i}' for i in range(size)]):
        print('[PASS]')
    else:
        print('[FAIL]')


def test_big_dir():
    os.chdir(sys.argv[1])
    dname = "bigdir"
    os.system(f"mkdir -p {dname}")

    # 1 block
    print('[TEST] dir using 1 direct block')
    make_dir(16, dname, 'dir1')
    # 2 block
    print('[TEST] dir using 2 direct blocks')
    make_dir(32, dname, 'dir2')
    # 128 indirect block + 2 direct block
    print('[TEST] dir using indirect blocks')
    make_dir(16 * 130, dname, 'dir3')
    # use all double indirect block
    print('[TEST] dir using double indirect blocks (takes a lot of time...)')
    make_dir(16 * 260, dname, 'dir4')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} MOUNTPOINT ')
        exit()

    print(f"ROOT is {sys.argv[1]}")

    test_big_file()
    test_big_dir()
