import threading, json, os, datetime, queue
from scapy.all import sniff, IP

class FirewallEngine:
    def __init__(self, log_queue):
        self.log_queue = log_queue
        self.running = False
        self.blocked_ips = []
        self.rules_path = "core/rules.json"
        self.logs_dir = "logs"
        self.session_logs = []
        self.load_rules()

    def load_rules(self):
        for f in ["core", self.logs_dir]: 
            if not os.path.exists(f): os.makedirs(f)
        if not os.path.exists(self.rules_path):
            with open(self.rules_path, "w") as f: json.dump([], f)
        try:
            with open(self.rules_path, "r") as f: self.blocked_ips = json.load(f)
            for ip in self.blocked_ips: os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        except: self.blocked_ips = []

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.append(ip)
            with open(self.rules_path, "w") as f: json.dump(self.blocked_ips, f)
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            return True
        return False

    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            with open(self.rules_path, "w") as f: json.dump(self.blocked_ips, f)
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
            return True
        return False

    def packet_handler(self, pkt):
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
            now = datetime.datetime.now()
            d_str, t_str = now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")
            status = "BLOCKED" if src in self.blocked_ips else "ALLOWED"
            color = "#FF0055" if status == "BLOCKED" else "#39FF14"
            data = {"type": "packet", "date": d_str, "time": t_str, "src": src, "dst": dst, "status": status, "color": color}
            self.session_logs.append(f"[{d_str} {t_str}] {status}: {src} -> {dst}")
            self.log_queue.put(data)

    def start(self):
        if not self.running:
            self.running = True
            self.session_logs = []
            threading.Thread(target=lambda: sniff(prn=self.packet_handler, stop_filter=lambda x: not self.running, store=0), daemon=True).start()

    def stop(self):
        if self.running:
            self.running = False
            ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            fname = os.path.join(self.logs_dir, f"firewall_{ts}.log")
            with open(fname, "w") as f:
                f.write(f"KALI SHIELD PRO AUDIT - {ts}\n" + "="*30 + "\n")
                for line in self.session_logs: f.write(line + "\n")
            return fname
