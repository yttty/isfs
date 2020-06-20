#! /bin/python3
import os
import sys


def test_small():
    os.chdir(sys.argv[1])
    cmds = [
        'ls', 'mkdir small', 'cd small', 'ls', 'touch file1',
        'echo hello >> file2', 'ls', 'cat file1', 'cat file2', 'rm file1',
        'ls', 'cd ..', 'rmdir small', 'ls'
    ]
    for cmd in cmds:
        print(f'[COMMAND] {cmd}')
        os.system(cmd)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} MOUNTPOINT ')
        exit()

    print(f"ROOT is {sys.argv[1]}")
    test_small()
