#!/usr/bin/env python3

"""
NEED TO REMOVE THE ARCHIVE FROM THE F5
NEED TO CHECK SPACE  BEFORE START
DISK FILLS FAST

172.31.60.1     faauryd01f502
172.31.60.2     faaueqx01f502
172.31.60.4     faauryd01f501
172.31.60.5     faaueqx01f501
"""

# library imports
import argparse
from netmiko import ConnectHandler
from paramiko import SSHClient
from scp import SCPClient

# local imports
from logger import Logger
from dateops import dateTimeStamp
import scp_python

def log_args(args, logger):
    """Write program arguments to logfile, using Logger object (logger.py)
    args is a namespace object, can't iterate over it directly"""

    for arg in vars(args):
        logger.debug("argument:  {}\tvalue:\t {}".format(arg, getattr(args, arg)))

def print_args(args):
    """print program arguments.
    args is a namespace object, can't iterate over it directly"""

    for arg in vars(args):
        print("argument:  {}\tvalue:\t {}".format(arg, getattr(args, arg)))


def new_archive_name(hostname):
    return hostname + "_" + dateTimeStamp() + ".tgz"

def new_f5archive_name(hostname):
    return hostname + "_" + dateTimeStamp()

def main():
    #
    # 1 setup arguments and parse them
    #
    parser = argparse.ArgumentParser(description="Run commands over SSH connection.")
    parser.add_argument(
        "-t", "--targethost", help="device to be backed up", required=True
    )
    parser.add_argument("-u", "--username", help="device login user", required=True)
    parser.add_argument(
        "-l", "--logfile", help="user specified log file", required=False
    )

    # either device file, or device list are needed
    device_source = parser.add_mutually_exclusive_group(required=True)
    device_source.add_argument("-p", "--password", help="device login password")
    device_source.add_argument(
        "-i", "--sshid", help="ssh key to use for authentication"
    )

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-q", "--quiet", action="store_true")
    verbosity_group.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    #
    # 2. setup logfile and level
    #
    if args.logfile:
        logfile = args.logfile
    else:
        logfile = Logger("sshbackup.log")

    logfile = Logger(logfile)

    if args.verbose:
        print_args(args)
        log_args(args, logfile)

    if args.verbose:
        logfile.info("Verbose")
    elif args.quiet:
        logfile.info("Quiet")
    else:
        logfile.info("Neither verbose nor quiet.")

    archive_name = new_f5archive_name(args.targethost)

    if args.sshid:
        device = ConnectHandler(
            device_type="linux",
            ip=args.targethost,
            username=args.username,
            use_keys=True,
            key_file=args.sshid,
        )
    elif args.password:
        device = ConnectHandler(
            device_type="linux",
            ip=args.targethost,
            username=args.username,
            password=args.password,
        )
    else:
        logfile.critical("No credentials, this won't work")
        exit

    # run f5 backup command
    #
    output = device.send_command("tmsh save /sys ucs " + archive_name)
    logfile.info(output)
    print(output)

    # run the checksum, this returns a multiline string, shenanigans

    full_archive_path = "/var/local/ucs/" + archive_name + ".ucs"
    logfile.info("full_archive_path {}".format(full_archive_path))
    output = device.send_command("/usr/bin/md5sum " + full_archive_path)

    logfile.info(output)

    for line in output.splitlines():
        if line.endswith("ucs"):
            archive_md5, new_archive = line.split()
            logfile.info("MD5 result: {}; archive name: {}".format(archive_md5, new_archive))
            if new_archive == archive_name:
                logfile.info("LOOKING GOOD, new_archive == archive_name")
        else:
            logfile.critical("problem with MD5 return")

    dstfile = "/var/log/fleet_f5/."
    scp_python.get_file_scp(args.targethost,full_archive_path, dstfile)


if __name__ == "__main__":
    main()


