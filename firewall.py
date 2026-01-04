import customtkinter as ctk
import os, queue
from core.engine import FirewallEngine

NEON_GREEN = "#39FF14"
PURE_BLACK = "#000000"
DARK_GRAY = "#111111"
ALERT_RED = "#FF0000"

class NeonFirewall(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("KALI SHIELD PRO v2.1")
        self.geometry("1400x850")
        self.configure(fg_color=PURE_BLACK)
        
        self.h_font = ("Courier New", 32, "bold")
        self.label_font = ("Arial", 16, "bold")
        self.data_font = ("Consolas", 15)

        self.log_queue = queue.Queue()
        self.engine = FirewallEngine(self.log_queue)

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=320, fg_color=DARK_GRAY, corner_radius=0, border_color=NEON_GREEN, border_width=1)
        self.sidebar.pack(side="left", fill="y")
        
        ctk.CTkLabel(self.sidebar, text="KALI SHIELD", text_color=NEON_GREEN, font=self.h_font).pack(pady=30)
        
        # Threat Meter Feature
        self.meter_label = ctk.CTkLabel(self.sidebar, text="SYSTEM STATUS", font=self.label_font, text_color="white")
        self.meter_label.pack(pady=(10, 0))
        self.threat_meter = ctk.CTkLabel(self.sidebar, text="● SAFE", font=("Arial", 28, "bold"), text_color=NEON_GREEN)
        self.threat_meter.pack(pady=5)

        self.start_btn = ctk.CTkButton(self.sidebar, text="START SCAN", fg_color=PURE_BLACK, border_color=NEON_GREEN, border_width=2, text_color=NEON_GREEN, command=self.start_firewall)
        self.start_btn.pack(pady=10, padx=25)

        self.stop_btn = ctk.CTkButton(self.sidebar, text="STOP & SAVE", fg_color=PURE_BLACK, border_color="#FF0055", border_width=2, text_color="#FF0055", command=self.stop_firewall, state="disabled")
        self.stop_btn.pack(pady=10, padx=25)

        # IP Ban Hammer
        self.ip_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Enter IP...", fg_color=PURE_BLACK, border_color=NEON_GREEN)
        self.ip_entry.pack(pady=20, padx=25)
        
        btn_f = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        btn_f.pack()
        ctk.CTkButton(btn_f, text="BLOCK", fg_color="#C0392B", width=100, command=self.add_block).pack(side="left", padx=5)
        ctk.CTkButton(btn_f, text="UNBLOCK", fg_color="#7F8C8D", width=100, command=self.remove_block).pack(side="left", padx=5)

        self.block_scroll = ctk.CTkScrollableFrame(self.sidebar, width=260, height=200, fg_color=PURE_BLACK, border_color=NEON_GREEN)
        self.block_scroll.pack(pady=20)
        self.refresh_block_list()

        # --- MONITORING AREA ---
        self.main_frame = ctk.CTkFrame(self, fg_color=PURE_BLACK)
        self.main_frame.pack(side="right", fill="both", expand=True, padx=20)

        self.status_header = ctk.CTkLabel(self.main_frame, text="FIREWALL IDLE", text_color=NEON_GREEN, font=("Courier New", 24, "bold"))
        self.status_header.pack(pady=20)
        
        h_frame = ctk.CTkFrame(self.main_frame, height=40, fg_color=DARK_GRAY)
        h_frame.pack(fill="x")
        cols = [("DATE", 130), ("TIME", 110), ("SOURCE", 220), ("DESTINATION", 220), ("STATUS", 180)]
        for text, width in cols:
            ctk.CTkLabel(h_frame, text=text, width=width, font=self.label_font, text_color=NEON_GREEN).pack(side="left", padx=5)

        self.log_scroll = ctk.CTkScrollableFrame(self.main_frame, fg_color=PURE_BLACK, border_color=NEON_GREEN, border_width=1)
        self.log_scroll.pack(fill="both", expand=True, pady=10)

        self.check_queue()

    def check_queue(self):
        try:
            while True:
                d = self.log_queue.get_nowait()
                # Update Threat Meter
                if d.get("threat_active"):
                    self.threat_meter.configure(text="● CRITICAL", text_color=ALERT_RED)
                else:
                    self.threat_meter.configure(text="● SAFE", text_color=NEON_GREEN)

                row = ctk.CTkFrame(self.log_scroll, fg_color="transparent")
                row.pack(fill="x")
                ctk.CTkLabel(row, text=d['date'], width=130, text_color="white", font=self.data_font).pack(side="left", padx=5)
                ctk.CTkLabel(row, text=d['time'], width=110, text_color="white", font=self.data_font).pack(side="left", padx=5)
                ctk.CTkLabel(row, text=d['src'], width=220, text_color=NEON_GREEN, font=self.data_font).pack(side="left", padx=5)
                ctk.CTkLabel(row, text=d['dst'], width=220, text_color="white", font=self.data_font).pack(side="left", padx=5)
                ctk.CTkLabel(row, text=d['status'], width=180, text_color=d['color'], font=("Arial", 15, "bold")).pack(side="left", padx=5)
                
                if len(self.log_scroll.winfo_children()) > 50: self.log_scroll.winfo_children()[0].destroy()
        except: pass
        self.after(100, self.check_queue)

    def refresh_block_list(self):
        for w in self.block_scroll.winfo_children(): w.destroy()
        for ip in self.engine.blocked_ips:
            ctk.CTkLabel(self.block_scroll, text=f"• {ip}", text_color="#FF5555", font=self.data_font).pack(anchor="w", padx=10)

    def start_firewall(self):
        self.engine.start()
        self.start_btn.configure(state="disabled"); self.stop_btn.configure(state="normal")
        self.status_header.configure(text="SCANNING LIVE TRAFFIC...")

    def stop_firewall(self):
        path = self.engine.stop()
        self.start_btn.configure(state="normal"); self.stop_btn.configure(state="disabled")
        self.status_header.configure(text=f"LOG SAVED: {os.path.basename(path)}")
        self.threat_meter.configure(text="● IDLE", text_color="gray")

    def add_block(self):
        ip = self.ip_entry.get().strip()
        if ip and self.engine.block_ip(ip): self.refresh_block_list(); self.ip_entry.delete(0, 'end')

    def remove_block(self):
        ip = self.ip_entry.get().strip()
        if ip and self.engine.unblock_ip(ip): self.refresh_block_list(); self.ip_entry.delete(0, 'end')

if __name__ == "__main__":
    if os.getuid() != 0: print("Sudo required!")
    else: NeonFirewall().mainloop()
