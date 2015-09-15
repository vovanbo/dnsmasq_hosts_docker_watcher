# dnsmasq_hosts_docker_watcher

Python-based daemon for watching docker events and update hosts file for DNSMasq.

This is Python fork of Ruby-based daemon [docker-dnsmaq](https://github.com/jaychris/docker-dnsmaq).
Using DNSMasq for lightweight service discovery with docker containers is also inspired by 
docker-log-analyzer by [zCirill](https://github.com/zCirill).

Only Python 2.7 is supported yet. No any 3rd-party dependencies needed.
Manually tested on Ubuntu 14.04 yet.

## Usage:

Place `dnsmasq_hosts_docker_watcher.py` to `/usr/local/etc/dnsmasq_hosts_docker_watcher.py`, for example. And run:

```bash
$ sudo python /usr/local/etc/dnsmasq_hosts_docker_watcher.py &
```

List of settings which can be overriden by CLI parameters:

- `-V` or `--version` — show version of daemon and exit
- `-D` or `--debug` turn on debug (default mode is no debug)
- `--hosts` — path to daemon's additional hosts file for DNSMasq (default: `/etc/docker_watcher_hosts`)
- `--watcher-pid` — path to daemon's watcher PID (default: `/var/run/docker_watcher.pid`)
- `--docker-pid` — path to Docker's PID (default: `/var/run/docker.pid`)
- `--dnsmasq-pid` — path to DNSMasq's PID (default: `/var/run/dnsmasq/dnsmasq.pid`)
- `--dnsmasq-user` — DNSMasq user (default: `dnsmasq`)


## Release History

0.2.3

- Fix README

0.2.2

- Properly handle SIGHUP.
- Fix bug with typecasting of container ID, when container ID is `<no value>`.

0.2.1

- Avoid duplicate of DNS records when FQDN and hostname is equally.

0.2.0

- Add host record with FQDN in DNSMasq hosts file.

0.1.0

- First release. Base functionality.

## License

Copyright &copy; 2015 Vladimir Bolshakov. Licensed under the GNU GPL v2.