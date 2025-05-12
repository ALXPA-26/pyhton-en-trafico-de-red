import scapy.all as scapy
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import threading
import os

# Diccionario para contar los paquetes por protocolo
packet_counts = {
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'Other': 0
}

# Lista para almacenar los paquetes capturados (para guardar en .pcap)
captured_packets = []

# Callback para cada paquete capturado
def packet_callback(packet):
    captured_packets.append(packet)  # Guardamos el paquete para el archivo .pcap
    if packet.haslayer('TCP'):
        packet_counts['TCP'] += 1
    elif packet.haslayer('UDP'):
        packet_counts['UDP'] += 1
    elif packet.haslayer('ICMP'):
        packet_counts['ICMP'] += 1
    else:
        packet_counts['Other'] += 1

# Función para actualizar el gráfico
def update_plot(frame):
    plt.cla()
    protocols = list(packet_counts.keys())
    counts = list(packet_counts.values())
    plt.bar(protocols, counts, color=['blue', 'green', 'red', 'grey'])
    plt.title('Monitor de Tráfico de Red')
    plt.ylabel('Número de Paquetes')
    plt.xlabel('Protocolo')
    plt.ylim(0, max(counts)+5)

# Función principal de captura
def main(interface_name, duration, pcap_path):
    print(f"\n[+] Iniciando captura en {interface_name} durante {duration} segundos...")
    scapy.sniff(iface=interface_name, prn=packet_callback, timeout=duration)
    
    print(f"[+] Guardando captura en: {pcap_path}")
    scapy.wrpcap(pcap_path, captured_packets)
    print("[+] Captura finalizada y guardada.")

# Código principal
if __name__ == "__main__":
    print("Interfaces disponibles en tu equipo:\n")
    scapy.show_interfaces()

    INTERFACE = input("\n🔌 Ingresa el nombre exacto de la interfaz de red (Ej. 'Wi-Fi' o 'Ethernet'): ")
    DURATION = int(input("⏱️ Ingresa la duración de la captura en segundos: "))
    FILENAME = input("💾 Ingresa el nombre del archivo de salida (ej. captura.pcap): ")
    FOLDER = input("📁 Ingresa la ruta completa donde deseas guardar el archivo (ej. C:/Users/Desktop): ")

    # Asegura que el nombre tenga extensión .pcap
    if not FILENAME.endswith('.pcap'):
        FILENAME += '.pcap'

    PCAP_PATH = os.path.join(FOLDER, FILENAME)

    # Preparar ventana de gráficos
    fig = plt.figure()
    ani = animation.FuncAnimation(fig, update_plot, interval=1000)

    # Lanzar captura en un hilo separado
    sniff_thread = threading.Thread(target=main, args=(INTERFACE, DURATION, PCAP_PATH))
    sniff_thread.daemon = True
    sniff_thread.start()

    # Mostrar gráfico
    plt.show()
