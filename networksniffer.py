from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

# Sniffing packets
sniff(prn=packet_callback, count=10)


import tkinter as tk
from scapy.all import sniff
import threading

class NetworkSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.sniffing = False

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.output_text = tk.Text(root, height=20, width=80)
        self.output_text.pack(pady=10)

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.display_packet, stop_filter=self.stop_sniffing_filter)

    def display_packet(self, packet):
        if self.sniffing:
            self.output_text.insert(tk.END, f"{packet.summary()}\n")
            self.output_text.see(tk.END)

    def stop_sniffing_filter(self, packet):
        return not self.sniffing

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSnifferApp(root)
    root.mainloop()