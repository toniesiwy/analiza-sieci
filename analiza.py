from scapy.all import ARP, Ether, srp, sniff
import socket
import os

# Funkcja skanująca ARP
def scan_arp(target_ip):
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices

# Funkcja do sniffingu pakietów
def packet_callback(packet):
    print(packet.show())

def sniff_packets(timeout=10, count=10):
    print(f"Rozpoczynam sniffing... (limit: {count} pakietów lub {timeout} sekund)")
    
    # Zmienna do przechowywania liczby przechwyconych pakietów
    packet_count = 0

    # Funkcja warunkowa do zakończenia sniffingu
    def stop_sniffing(packet):
        nonlocal packet_count
        packet_count += 1
        print(f"Pakiet #{packet_count}: {packet.summary()}")
        if packet_count >= count:
            print("Osiągnięto limit pakietów. Zatrzymywanie sniffingu.")
            return True  # Zatrzymanie sniffingu po osiągnięciu limitu
        return False

    # Sniffing pakietów z limitem czasowym i liczbowym
    sniff(prn=packet_callback, stop_filter=stop_sniffing, timeout=timeout, store=0)

# Funkcja skanowania portów
def scan_ports(target_ip, target_ports):
    open_ports = []
    for port in target_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
            print(f"Port {port} jest OTWARTY")
        else:
            print(f"Port {port} jest ZAMKNIĘTY")
        sock.close()
    return open_ports

# Funkcja sprawdzająca dostępność hosta
def check_host_availability(target_ip):
    response = os.system(f"ping -c 1 {target_ip}")
    if response == 0:
        print(f"Host {target_ip} jest dostępny.")
        return True
    else:
        print(f"Host {target_ip} jest niedostępny.")
        return False

# Menu wyboru funkcji
def main():
    print("Wybierz akcję:")
    print("1 - Skanowanie ARP")
    print("2 - Sniffing pakietów")
    print("3 - Skanowanie portów")
    choice = input("Wybór: ")

    if choice == "1":
        target_ip = input("Podaj zakres IP do skanowania (np. 192.168.1.1/24): ")
        devices = scan_arp(target_ip)
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
    elif choice == "2":
        # Użytkownik może podać czas i liczbę pakietów do sniffingu
        timeout = int(input("Podaj czas sniffingu w sekundach: "))
        count = int(input("Podaj liczbę pakietów do przechwycenia: "))
        sniff_packets(timeout=timeout, count=count)
    elif choice == "3":
        target_ip = input("Podaj IP hosta do skanowania (np. 192.168.100.28): ")
        if check_host_availability(target_ip):  # Sprawdzamy dostępność hosta
            target_ports = list(map(int, input("Podaj porty do skanowania (oddzielone przecinkiem): ").split(',')))
            open_ports = scan_ports(target_ip, target_ports)
            if open_ports:
                print("Otwórz porty:", open_ports)
            else:
                print("Brak otwartych portów.")
    else:
        print("Niepoprawny wybór.")

if __name__ == "__main__":
    main()
