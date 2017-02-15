
import argparse
from os.path import join as pjoin, isdir
import sys


sysfs_base = pjoin('/', 'sys', 'distributed-tracer')


class ControllerException(Exception):
    pass


def check_sysfs():
    """
    Checks if the sysfs directory is present
    """
    if not isdir(pjoin(sysfs_base)):
        raise ControllerException('%s does not exist, is the kernel module loaded?' % sysfs_base)


def xxx_pid(name, args):
    """
    Writes into the <name>_pid file a list of pids
    :param name: The prefix of the file
    :param args: The cmd line args
    """
    pids = set(args.pids)
    pid_file_path = pjoin(sysfs_base, '%s_pid' % name)
    try:
        pid_file = open(pid_file_path, 'w')
        for pid in pids:
            print(pid)
            pid_file.write(pid.strip())
            pid_file.flush() # To write immediatly into the file without any buffering
    except OSError:
        raise ControllerException('Failed to open %s, do you have permission ?' % pid_file_path)


def add_pid(args):
    """
    Adds a list of pids to the watchlist
    :param args: Cmd line args
    """
    xxx_pid('add', args)


def remove_pid(args):
    """
    Removes a list of pids from the watchlist
    :param args: Cmd line args
    """
    xxx_pid('remove', args)


def list_pid(_):
    """
    Lists the PIDs in the watchlist
    """
    list_pid_file_path = pjoin(sysfs_base, 'list_pid')
    try:
        list_pid_file = open(list_pid_file_path, 'r')
        sys.stdout.write(list_pid_file.read())
    except OSError:
        raise ControllerException('Failed to open %s, do you have permission ?' % list_pid_file_path)


def mod_probe(value):
    """
    Sets the value of the probe file
    :param value: The value to set
    """
    probe_file_path = pjoin(sysfs_base, 'probe')
    try:
        probe_file = open(probe_file_path, 'w')
        probe_file.write(str(value))
    except OSError:
        raise ControllerException('Failed to open %s, do you have permission ?' % probe_file_path)


def set_probe(_):
    """
    Activates the probe
    """
    mod_probe(1)


def unset_probe(_):
    """
    Deactivates the probe
    """
    mod_probe(0)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    pid_parser = subparsers.add_parser('pid')
    probe_parser = subparsers.add_parser('probe')

    pid_subparsers = pid_parser.add_subparsers()
    add_pid_parser = pid_subparsers.add_parser('add')
    remove_pid_parser = pid_subparsers.add_parser('remove')
    list_pid_parser = pid_subparsers.add_parser('list')

    probe_subparsers = probe_parser.add_subparsers()
    set_probe_parser = probe_subparsers.add_parser('set')
    unset_probe_parser = probe_subparsers.add_parser('unset')

    add_pid_parser.set_defaults(func=add_pid)
    add_pid_parser.add_argument('pids', nargs='+', help='The list of PIDs to add')

    remove_pid_parser.set_defaults(func=remove_pid)
    remove_pid_parser.add_argument('pids', nargs='+', help='The list of PIDs to remove')

    list_pid_parser.set_defaults(func=list_pid)

    set_probe_parser.set_defaults(func=set_probe)

    unset_probe_parser.set_defaults(func=unset_probe)

    args = parser.parse_args()
    try:
        check_sysfs()
        args.func(args)
    except AttributeError:
        parser.print_help()
        exit(1)
    except ControllerException as e:
        print('Error: %s' % e.args[0], file=sys.stderr)
        exit(1)


if __name__ == '__main__':
    main()
