#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import argparse
import os
import re
import shutil
import signal
import logging
import tempfile
import time
import sys
import subprocess
import errno
import socket
import pwd

VERSION = '0.2.0'
events = None


def pid_exists(pid):
    """
    Check whether pid exists in the current process table. UNIX only.
    http://stackoverflow.com/a/6940314/3890323
    """
    if pid < 0:
        return False
    if pid == 0:
        # According to "man 2 kill" PID 0 refers to every process
        # in the process group of the calling process.
        # On certain systems 0 is a valid PID but we have no way
        # to know that in a portable fashion.
        raise ValueError('invalid PID 0')
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH == No such process
            return False
        elif err.errno == errno.EPERM:
            # EPERM clearly means there's a process to deny access to
            return True
        else:
            # According to "man 2 kill" possible error values are
            # (EINVAL, EPERM, ESRCH)
            raise
    else:
        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Daemon for watching docker events '
                    'and update hosts file for DNSMasq'
    )
    parser.add_argument('-V', '--version', action='store_true',
                        help='Show version of daemon and exit')
    parser.add_argument('-D', '--debug', action='store_true',
                        help='Debug mode (default: %(default)s)')
    parser.add_argument('--hosts', dest='hosts', type=str,
                        help='Hosts file (default: %(default)s)',
                        default='/etc/docker_watcher_hosts')
    parser.add_argument('--watcher-pid', dest='watcher_pidfile', type=str,
                        help='Watcher PID file (default: %(default)s)',
                        default='/var/run/docker_watcher.pid')
    parser.add_argument('--docker-pid', dest='docker_pidfile', type=str,
                        help='Docker PID file (default: %(default)s)',
                        default='/var/run/docker.pid')
    parser.add_argument('--dnsmasq-pid', dest='dnsmasq_pidfile', type=str,
                        help='DNSMasq PID file (default: %(default)s)',
                        default='/var/run/dnsmasq/dnsmasq.pid')
    parser.add_argument('--local-domain', dest='local_domain', type=str,
                        help='Local domain name without dot '
                             '(default: %(default)s)',
                        default='local')
    parser.add_argument('--dnsmasq-user', dest='dnsmasq_user', type=str,
                        help='DNSMasq service user (default: %(default)s)',
                        default='dnsmasq')
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        sys.exit()

    logFormatter = logging.Formatter(
        "%(asctime)s [%(levelname)-5.5s]  %(message)s"
    )
    logger = logging.getLogger('docker_watcher')

    if args.debug:
        logger.setLevel(logging.DEBUG)
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        console.setFormatter(logFormatter)
        logger.addHandler(console)
    else:
        logger.setLevel(logging.WARNING)


    def interrupt_handler(signum, frame):
        logger.info('Caught signal {0}. Exiting...'.format(signum))
        os.unlink(args.watcher_pidfile)
        if isinstance(events, subprocess.Popen):
            events.kill()
        sys.exit()


    signal.signal(signal.SIGINT, interrupt_handler)
    signal.signal(signal.SIGTERM, interrupt_handler)

    with open(args.watcher_pidfile, 'w+') as f:
        f.write(str(os.getpid()))

    logger.info('Starting DNSMasq Docker watcher')

    start_waiting_at = time.time()
    while not os.path.exists(args.docker_pidfile):
        now = time.time()
        if now - start_waiting_at > 600:
            logging.fatal('Docker daemon still not started after 10 minutes... '
                          'Please contact your system administrator!')
            sys.exit(1)

        logging.warning('Docker daemon is not running yet...')
        time.sleep(5)

    logger.info('Docker Daemon Up! - Listening for events...')

    try:
        events = subprocess.Popen(['docker', 'events'], stdout=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        logger.fatal('Cannot run "docker events".')
        sys.exit(1)

    cid_pattern = re.compile(r'^.*([0-9a-f]{64}).*$', re.IGNORECASE)

    while True:
        line = events.stdout.readline()
        if line:
            event = line.split()[-1]
            cid_long = cid_pattern.search(line).group(1)
            cid_short = cid_long[:12]

            logger.debug('Event fired ({0}): {1}'.format(cid_long, event))

            # START EVENT
            if event == 'start':
                inspect_fmt = '{{.NetworkSettings.IPAddress}}|' \
                              '{{.Name}}|' \
                              '{{.State.Pid}}'
                inspect_cmd = 'docker inspect ' \
                              '--format="{0}" {1}'.format(inspect_fmt, cid_long)
                try:
                    container_info = subprocess.check_output(inspect_cmd,
                                                             shell=True)
                except subprocess.CalledProcessError as e:
                    logger.fatal('Cannot run "docker inspect".')
                    sys.exit(1)

                container_info = container_info.strip().split('|')
                logger.debug(container_info)
                ip, name, cpid = container_info
                name = name.strip('/')
                cpid = int(cpid)

                if not cpid or not pid_exists(cpid):
                    logger.error(
                        'Could not find a process indentifier '
                        'for container {0}. '
                        'Cannot update DNS.'.format(cid_short)
                    )
                    continue

                host_record = '{ip} ' \
                              '{name}.{fqdn} ' \
                              '{name}.{host} ' \
                              '{name}.{local} ' \
                              '{cid}\n'.format(ip=ip,
                                               name=name,
                                               fqdn=socket.getfqdn(),
                                               host=socket.gethostname(),
                                               local=args.local_domain,
                                               cid=cid_short)
                if os.path.exists(args.hosts):
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        for line in open(args.hosts):
                            if cid_short not in line:
                                tmp.write(line)
                    shutil.move(tmp.name, args.hosts)
                with open(args.hosts, 'a+') as f:
                    try:
                        f.write(host_record)
                    except IOError:
                        logger.error(
                            'Could not update DNSMasq record for '
                            '{0}.'.format(cid_short)
                        )
                        continue
                # Set owner and permissions to hosts file
                try:
                    uid = pwd.getpwnam(args.dnsmasq_user).pw_uid
                except KeyError as e:
                    uid = pwd.getpwnam('root').pw_uid
                os.chown(f.name, uid, -1)
                os.chmod(f.name, 0640)

                logger.debug(
                    'Updated DNSMasq, Added record for {0}: {1}'.format(
                        cid_short, host_record.strip()
                    )
                )
                kill_result = subprocess.call(
                    'kill -s HUP $(cat {0})'.format(args.dnsmasq_pidfile),
                    shell=True
                )
                logger.debug(
                    'DNSMasq restarted (result: {0}).'.format(kill_result)
                )

            # STOP EVENT
            elif event == 'stop' or event == 'die':
                if os.path.exists(args.hosts):
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        for line in open(args.hosts):
                            if cid_short not in line:
                                tmp.write(line)
                    shutil.move(tmp.name, args.hosts)
                logger.debug(
                    'Updated DNSMasq. Removed record for {0}'.format(cid_short)
                )
                kill_result = subprocess.call(
                    'kill -s HUP $(cat {0})'.format(args.dnsmasq_pidfile),
                    shell=True
                )
                logger.debug(
                    'DNSMasq restarted (result: {0}).'.format(kill_result)
                )
