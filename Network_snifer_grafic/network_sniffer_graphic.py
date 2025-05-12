# Network_Sniffer_Graphic.py

#Importar descapy para captura de paquetes
import scapy.all as scapy
# importar matplotlip para lo g´raficos
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import threading

# crear el diccionario para contar lo paquetes
# de cada protocolo
packet_counts = {
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'Other': 0 # para protocolos desconocidos
}
# Función que se llama cada vez que se capt un paquee
def packet_callback(packet):
    if packet.haslayer('TCP'):
        packet_counts['TCP'] += 1
    elif packet.haslayer('UDP'):
        packet_counts['UDP'] += 1
    elif packet.haslayer('ICMP'):
        packet_callback['ICMP'] += 1
    else:
        packet_counts['Other'] += 1

# Función que actualiza la gráfica cada cierto intervalo de tiempo
def update_plot(frame):
    plt.cla() # limpia el gráfico
    protocols = list(packet_counts.keys()) # Lista de protocolos
    counts = list(packet_counts.values()) # lista cantidades de paquetes
    #crear un gráfico de barrras con los datos 
    plt.bar(protocols, counts, color= ['blue', 'green', 'red', 'grey'])
    plt.title('Monitor de Tráfico de Red') # Título del gráfico
    plt.ylabel('Número de Paquetes')
    plt.xlabel('Protocolo')
    plt.ylim(0, max(counts)+5)

# fuincion principal de captura
def main(interface_name):
    print(f"Iniciando captura de paquetes en la interfaz: {interface_name}...")
    scapy.sniff(prn=packet_callback, store=0, iface=interface_name)

# código principal que se ejecuta al correr el archivo
if __name__ == "__main__":
    print("Interfaces disponibles en tu equipo:\n")
    scapy.show_interfaces()

    INTERFACE = input("\nIngresa el nombre exacto de la interfaz que deseas usar (por ejemplo 'Wi-Fi' o 'Ethernet'): ")

    #crea una figura (ventana) para mostrar la gráfica
    fig = plt.figure()
    # Asocioa la función update_plot para actualizar ña grafica
    ani = animation.FuncAnimation(fig, update_plot, interval=1000)



    sniff_thread = threading.Thread(target=main, args=(INTERFACE,))
    sniff_thread.deamon = True
    sniff_thread.start()

        #muestra la gráfica ()
plt.show()
