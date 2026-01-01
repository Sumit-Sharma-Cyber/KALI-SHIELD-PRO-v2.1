import customtkinter as ctk
import os, queue
from core.engine import FirewallEngine

NEON_GREEN = "#39FF14"
PURE_BLACK = "#000000"
DARK_GRAY = "#111111"

ctk.set_appearance_mode("dark")

class NeonFirewall(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("KALI SHIELD PRO v2.0 - Developer: Sumit Sharma")
        self.geometry("1300x800")
        self.configure(fg_color=PURE_BLACK)
        
        self.log_queue = queue.Queue()
        self.engine = FirewallEngine(self.log_queue)

        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=320, fg_color=DARK_GRAY, corner_radius=0, border_color=NEON_GREEN, border_width=1)
        self.sidebar.pack(side="left", fill="y")
        
        ctk.CTkLabel(self.sidebar, text="KALI SHIELD", text_color=NEON_GREEN, font=("Courier New", 28, "bold")).pack(pady=30)
        
        self.start_btn = ctk.CTkButton(self.sidebar, text="START SCAN", fg_color=PURE_BLACK, border_color=NEON_GREEN, border_width=2, text_color=NEON_GREEN, hover_color="#1A3300", command=self.start_firewall)
        self.start_btn.pack(pady=10, padx=20)

        self.stop_btn = ctk.CTkButton(self.sidebar, text="STOP & SAVE", fg_color=PURE_BLACK, border_color="#FF0055", border_width=2, text_color="#FF0055", command=self.stop_firewall, state="disabled")
        self.stop_btn.pack(pady=10, padx=20)

        ctk.CTkLabel(self.sidebar, text="________________________", text_color=NEON_GREEN).pack()
        
        ctk.CTkLabel(self.sidebar, text="IP BAN HAMMER", text_color=NEON_GREEN, font=("Arial", 14, "bold")).pack(pady=15)
        self.ip_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Target IP...", fg_color=PURE_BLACK, border_color=NEON_GREEN, text_color=NEON_GREEN)
        self.ip_entry.pack(pady=5, padx=20)
        
        btn_f = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        btn_f.pack(pady=10)
        ctk.CTkButton(btn_f, text="BLOCK", fg_color="#C0392B", width=90, command=self.add_block).pack(side="left", padx=5)
        ctk.CTkButton(btn_f, text="UNBLOCK", fg_color="#7F8C8D", width=90, command=self.remove_block).pack(side="left", padx=5)

        ctk.CTkLabel(self.sidebar, text="ACTIVE DEFENSES", text_color=NEON_GREEN, font=("Arial", 12, "bold")).pack(pady=(20,0))
        self.block_scroll = ctk.CTkScrollableFrame(self.sidebar, width=240, height=280, fg_color=PURE_BLACK, border_color=NEON_GREEN, border_width=1)
        self.block_scroll.pack(pady=10, padx=20)
        
        self.refresh_block_list()
        ctk.CTkButton(self.sidebar, text="📂 OPEN LOGS", fg_color="#34495E", command=lambda: os.system("xdg-open logs/")).pack(side="bottom", pady=20)

        # --- Main Monitoring Area ---
        self.main_frame = ctk.CTkFrame(self, fg_color=PURE_BLACK)
        self.main_frame.pack(side="right", fill="both", expand=True, padx=20)

        self.status_label = ctk.CTkLabel(self.main_frame, text="SYSTEM IDLE", text_color=NEON_GREEN, font=("Courier New", 18, "bold"))
        self.status_label.pack(pady=20)
        
        self.h_frame = ctk.CTkFrame(self.main_frame, height=40, fg_color=DARK_GRAY)
        self.h_frame.pack(fill="x", padx=5)
        cols = [("DATE", 120), ("TIME", 100), ("SOURCE", 200), ("DESTINATION", 200), ("STATUS", 120)]
        for text, width in cols:
            ctk.CTkLabel(self.h_frame, text=text, width=width, font=("Arial", 12, "bold"), text_color=NEON_GREEN).pack(side="left", padx=5)

        self.log_scroll = ctk.CTkScrollableFrame(self.main_frame, fg_color=PURE_BLACK, border_color=NEON_GREEN, border_width=1)
        self.log_scroll.pack(fill="both", expand=True, pady=10)

        self.check_queue()

    def refresh_block_list(self):
        for w in self.block_scroll.winfo_children(): w.destroy()
        for ip in self.engine.blocked_ips:
            ctk.CTkLabel(self.block_scroll, text=f"• {ip}", text_color="#FF5555", font=("Consolas", 12)).pack(anchor="w", padx=10)

    def start_firewall(self):
        self.engine.start()
        self.start_btn.configure(state="disabled"); self.stop_btn.configure(state="normal")
        self.status_label.configure(text="NETWORK OVERWATCH ACTIVE", text_color=NEON_GREEN)

    def stop_firewall(self):
        path = self.engine.stop()
        self.start_btn.configure(state="normal"); self.stop_btn.configure(state="disabled")
        self.status_label.configure(text=f"SESSION ARCHIVED: {os.path.basename(path)}", text_color="yellow")

    def add_block(self):
        ip = self.ip_entry.get().strip()
        if ip and self.engine.block_ip(ip): self.refresh_block_list(); self.ip_entry.delete(0, 'end')

    def remove_block(self):
        ip = self.ip_entry.get().strip()
        if ip and self.engine.unblock_ip(ip): self.refresh_block_list(); self.ip_entry.delete(0, 'end')

    def check_queue(self):
        try:
            while True:
                d = self.log_queue.get_nowait()
                row = ctk.CTkFrame(self.log_scroll, fg_color="transparent")
                row.pack(fill="x")
                ctk.CTkLabel(row, text=d['date'], width=120, text_color="white").pack(side="left", padx=5)
                ctk.CTkLabel(row, text=d['time'], width=100, text_color="white").pack(side="left", padx=5)
                ctk.CTkLabel(row, text=d['src'], width=200, text_color=NEON_GREEN).pack(side="left", padx=5)
                ctk.CTkLabel(row, text=d['dst'], width=200, text_color="white").pack(side="left", padx=5)
                ctk.CTkLabel(row, text=d['status'], width=120, text_color=d['color'], font=("bold", 12)).pack(side="left", padx=5)
                c = self.log_scroll.winfo_children()
                if len(c) > 100: c[0].destroy()
        except: pass
        self.after(100, self.check_queue)

if __name__ == "__main__":
    if os.getuid() != 0: print("Sudo required!")
    else: NeonFirewall().mainloop()
