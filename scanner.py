import click
import ipaddress
import platform
import subprocess
from scapy.all import ICMP, IP, sr1, conf

def os_ping(ip):
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    result = subprocess.run(
        ["ping", count_flag, "1", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0

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
        if net.prefixlen >= 30:  # likely a single host or public IP
            alive = os_ping(ip)
        else:
            pkt = IP(dst=str(ip))/ICMP()
            resp = sr1(pkt, timeout=1, verbose=False)
            alive = resp is not None

        if alive:
            click.echo(f"Host up: {ip}")
        else:
            click.echo(f"No response: {ip}")

if __name__ == '__main__':
    scan()
