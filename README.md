# Usage

```
sudo rm crash_*
sudo rm worker_*
sudo python -m slimDNS --address 10.0.0.1 --interface DNSServer --thread-socket ./test.socket
```

# Dev setup

```
ip netns add DNSClientNS
ip link add name DNSServer type bridge
ip netns exec DNSClientNS ip link add name DNSClient type bridge
ip link add name DNS-S type veth peer name DNS-C
ip link set dev DNS-S netns DNSClientNS
ip addr add 10.0.0.1/24 dev DNSServer
ip link set dev DNSServer up
ip link set dev DNS-C up
ip netns exec DNSClientNS ip addr add 10.0.0.2/24 dev DNSClient
ip netns exec DNSClientNS ip link set dev DNSClient up
ip netns exec DNSClientNS ip link set dev DNS-S up
```

# Testing

```
ip netns exec DNSClientNS dig +trace @10.0.0.1 hvornum.se
```