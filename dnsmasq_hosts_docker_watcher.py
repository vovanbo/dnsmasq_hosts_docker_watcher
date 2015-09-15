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

VERSION = '0.3.0-dev'

log = logging.getLogger('dnsmasq_hosts_docker_watcher')


class DaemonError(Exception):
    pass


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


def print_version():
    print(VERSION)


def setup_signal_handlers(args, event_listener):
    def interrupt_handler(signum, frame):
        log.info('Caught signal {0}. Exiting...'.format(signum))
        os.unlink(args.watcher_pidfile)
        log.debug('PID file {0} removed.'.format(args.watcher_pidfile))
        if isinstance(event_listener, subprocess.Popen):
            event_listener.kill()
            log.debug('Docker events listener is killed.')
        sys.exit()

    signal.signal(signal.SIGINT, interrupt_handler)
    signal.signal(signal.SIGTERM, interrupt_handler)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


def create_pid_file(args):
    with open(args.watcher_pidfile, 'w+') as f:
        f.write(str(os.getpid()))
    log.debug('PID file {0} created'.format(args.watcher_pidfile))


def check_or_wait_for_docker_daemon(args):
    log.info('Wait for Docker daemon...')
    start_waiting_at = time.time()
    while not os.path.exists(args.docker_pidfile):
        now = time.time()
        if now - start_waiting_at > 600:
            raise DaemonError(
                'Docker daemon still not started after 10 minutes... '
                'Please contact your system administrator!'
            )

        log.warning('Docker daemon is not running yet...')
        time.sleep(5)
    log.info('Docker daemon up!')


def setup_logging(args):
    log_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)-5.5s]  %(message)s")

    log_file = logging.FileHandler(args.log_file)
    log_file.setFormatter(log_formatter)

    if args.debug:
        log.setLevel(logging.DEBUG)
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        console.setFormatter(log_formatter)
        log.addHandler(console)
        log_file.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.WARNING)
        log_file.setLevel(logging.WARNING)

    log.addHandler(log_file)


def run_docker_event_listener():
    log.info('Listening for events...')
    try:
        return subprocess.Popen(['docker', 'events'], stdout=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        raise DaemonError('Cannot run "docker events".')


def run_event_parser(args, event_listener):
    cid_pattern = re.compile(r'^.*([0-9a-f]{64}).*$', re.IGNORECASE)
    fqdn = socket.getfqdn()

    while True:
        line = event_listener.stdout.readline()
        if line:
            event = line.split()[-1]
            cid_long = cid_pattern.search(line).group(1)
            cid_short = cid_long[:12]

            log.debug('Event fired ({0}): {1}'.format(cid_long, event))

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
                    raise DaemonError('Cannot run "docker inspect".')

                container_info = container_info.strip().split('|')
                log.debug(container_info)
                ip, name, cpid = container_info
                name = name.strip('/')
                try:
                    cpid = int(cpid)
                except ValueError as e:
                    log.error(e.message)
                    continue

                if not cpid or not pid_exists(cpid):
                    log.error(
                        'Could not find a process indentifier '
                        'for container {0}. '
                        'Cannot update DNS.'.format(cid_short)
                    )
                    continue

                dns_record = '{ip} {name}.{fqdn} {cid}'.format(ip=ip,
                                                               name=name,
                                                               fqdn=fqdn,
                                                               cid=cid_short)
                if os.path.exists(args.hosts):
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        for line in open(args.hosts):
                            if cid_short not in line:
                                tmp.write(line)
                    shutil.move(tmp.name, args.hosts)

                with open(args.hosts, 'a+') as f:
                    try:
                        f.write(dns_record + '\n')
                    except IOError:
                        log.error(
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

                log.debug(
                    'Updated DNSMasq. Added record for {0}: {1}'.format(
                        cid_short, dns_record
                    )
                )
                kill_result = subprocess.call(
                    'kill -s HUP $(cat {0})'.format(args.dnsmasq_pidfile),
                    shell=True
                )
                log.debug(
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
                log.debug(
                    'Updated DNSMasq. Removed record for {0}'.format(cid_short)
                )
                kill_result = subprocess.call(
                    'kill -s HUP $(cat {0})'.format(args.dnsmasq_pidfile),
                    shell=True
                )
                log.debug(
                    'DNSMasq restarted (result: {0}).'.format(kill_result)
                )


def _run():
    parser = argparse.ArgumentParser(
        description='Daemon for watching and parsing docker events, '
                    'collecting containers IPs '
                    'and updating hosts file for DNSMasq'
    )
    parser.add_argument('-V', '--version', action='store_true',
                        help='Show version of daemon and exit')
    parser.add_argument('-D', '--debug', action='store_true',
                        help='Debug mode (default: %(default)s)')
    parser.add_argument('-L', '--log-file', dest='log_file', type=str,
                        help='Log to file (default: %(default)s)',
                        default='/var/log/docker_watcher.log')
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
        return print_version()

    setup_logging(args)
    log.info('Starting DNSMasq Docker watcher daemon')
    create_pid_file(args)
    check_or_wait_for_docker_daemon(args)
    event_listener = run_docker_event_listener()
    setup_signal_handlers(args, event_listener)
    run_event_parser(args, event_listener)


def main():
    """
    Execute daemon
    :return:
    """
    try:
        return _run()
    except DaemonError as e:
        log.error(e.message)


if __name__ == '__main__':
    main()
