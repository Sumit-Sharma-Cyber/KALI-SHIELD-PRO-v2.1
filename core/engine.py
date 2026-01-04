import threading, json, os, datetime, queue, ipaddress, time
from scapy.all import sniff, IP, ICMP

class FirewallEngine:
    def __init__(self, log_queue):
        self.log_queue = log_queue
        self.running = False
        self.blocked_ips = []
        self.rules_path = "core/rules.json"
        self.logs_dir = "logs"
        self.session_logs = []
        self.last_attack_time = 0 
        self.load_rules()

    def load_rules(self):
        for f in ["core", self.logs_dir]: 
            if not os.path.exists(f): os.makedirs(f)
        if not os.path.exists(self.rules_path):
            with open(self.rules_path, "w") as f: json.dump([], f)
        try:
            with open(self.rules_path, "r") as f: self.blocked_ips = json.load(f)
            for ip in self.blocked_ips: 
                os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
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
            
            try:
                ip_obj = ipaddress.ip_address(src)
                is_local = ip_obj.is_private or ip_obj.is_loopback
                net_type = "LOCAL" if is_local else "OUTSIDE"
            except:
                net_type = "UNKNOWN"; is_local = False

            status = f"{net_type} ACCESS"
            color = "#39FF14" if is_local else "#E67E22"
            threat_detected = False

            if src in self.blocked_ips:
                status, color = "BLOCKED", "#FF0055"
                threat_detected = True
            elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                if not is_local:
                    status, color = "EXT-INTRUDER", "#FF0000"
                    threat_detected = True
                else:
                    status, color = "LOCAL-SCAN", "cyan"

            if threat_detected:
                self.last_attack_time = time.time()

            data = {
                "type": "packet", "date": d_str, "time": t_str, 
                "src": src, "dst": dst, "status": status, "color": color,
                "threat_active": (time.time() - self.last_attack_time < 30)
            }
            self.session_logs.append(f"[{d_str} {t_str}] {status}: {src} -> {dst}")
            self.log_queue.put(data)

    def start(self):
        if not self.running:
            self.running = True
            threading.Thread(target=lambda: sniff(prn=self.packet_handler, stop_filter=lambda x: not self.running, store=0), daemon=True).start()

    def stop(self):
        self.running = False
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        fname = os.path.join(self.logs_dir, f"firewall_{ts}.log")
        with open(fname, "w") as f:
            for line in self.session_logs: f.write(line + "\n")
        return fname
