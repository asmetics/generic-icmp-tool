import click
from scapy.all import ICMP, IP, sr1, conf
import ipaddress

@click.command()
@click.option('--target', prompt='Target IP/Subnet', help='The IP or subnet to scan (e.g., 192.168.1.0/24)')
def scan(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        click.echo(f"Invalid target: {e}")
        return

    click.echo(f"Scanning network: {net}")
    conf.verb = 0

    for ip in net.hosts():
        pkt = IP(dst=str(ip))/ICMP()
        resp = sr1(pkt, timeout=1, verbose=False)
        if resp is not None:
            click.echo(f"Host up: {ip}")
        else:
            click.echo(f"No response: {ip}")

if __name__ == '__main__':
    scan()
