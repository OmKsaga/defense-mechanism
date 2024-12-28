import socket
import threading
import logging
import tkinter as tk
from tkinter import scrolledtext

# Set up logging to track attacks
logging.basicConfig(filename='attack_logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Server Control")
        self.root.geometry("500x400")
        self.root.configure(bg="#f5f5f5")

        self.server = None
        self.server_thread = None
        self.is_running = False

        self.failed_attempts = {}
        self.banned_ips = {}
        self.MAX_ATTEMPTS = 3

        self.create_widgets()

    def create_widgets(self):
        self.status_label = tk.Label(self.root, text="Server Status: Stopped", font=("Arial", 14), bg="#f5f5f5", fg="red")
        self.status_label.pack(pady=20)

        self.toggle_button = tk.Button(self.root, text="Start Server", font=("Arial", 14, "bold"), bg="#4caf50", fg="white",
                                       activebackground="#45a049", activeforeground="white", width=15, command=self.toggle_server)
        self.toggle_button.pack(pady=10)

        self.log_display = scrolledtext.ScrolledText(self.root, width=50, height=15, wrap=tk.WORD, font=("Arial", 10))
        self.log_display.pack(pady=20)
        self.log_display.config(state=tk.DISABLED)

    def toggle_server(self):
        if self.is_running:
            self.stop_server()
        else:
            self.start_server()

    def start_server(self):
        self.server_thread = threading.Thread(target=self.run_server)
        self.server_thread.daemon = True
        self.server_thread.start()

        self.is_running = True
        self.status_label.config(text="Server Status: Running", fg="green")
        self.toggle_button.config(text="Stop Server", bg="#f44336", activebackground="#e53935")
        self.update_log("Server started...")

    def stop_server(self):
        if self.server:
            self.server.close()
            self.server = None

        self.is_running = False
        self.status_label.config(text="Server Status: Stopped", fg="red")
        self.toggle_button.config(text="Start Server", bg="#4caf50", activebackground="#45a049")
        self.update_log("Server stopped...")

    def update_log(self, message):
        self.log_display.config(state=tk.NORMAL)
        self.log_display.insert(tk.END, message + "\n")
        self.log_display.yview(tk.END)
        self.log_display.config(state=tk.DISABLED)

    def run_server(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind(("127.0.0.1", 9999))
            self.server.listen(5)
            self.update_log("Server is listening for connections...")

            while self.is_running:
                try:
                    client_socket, client_address = self.server.accept()
                    client_ip = client_address[0]

                    if client_ip in self.banned_ips:
                        reason = self.banned_ips[client_ip]
                        client_socket.send(f"Your IP is banned due to: {reason}\n".encode())
                        logging.info(f"Blocked IP {client_ip} attempted to connect. Reason: {reason}")
                        self.update_log(f"Blocked IP {client_ip} attempted to connect. Reason: {reason}")
                        client_socket.close()
                        continue

                    self.update_log(f"Connection from {client_ip}")
                    threading.Thread(target=self.handle_client, args=(client_socket, client_ip)).start()
                except Exception as e:
                    self.update_log(f"Error while accepting connections: {e}")

        except Exception as e:
            self.update_log(f"Server error: {e}")
            logging.error(f"Server error: {e}")

    def handle_client(self, client_socket, client_ip):
        failed_attempts = self.failed_attempts.get(client_ip, 0)

        while failed_attempts < self.MAX_ATTEMPTS:
            try:
                client_socket.send(f"Enter password (Attempts left: {self.MAX_ATTEMPTS - failed_attempts}): ".encode())
                password = client_socket.recv(1024).decode('utf-8').strip()

                if any(keyword in password.upper() for keyword in ["' OR", "--", "/*", "*/", "SELECT", "DROP", "INSERT"]):
                    self.ban_ip(client_ip, "SQL Injection detected")
                    client_socket.send(b"SQL Injection detected! Connection aborted.\n")
                    logging.info(f"SQL Injection attempt detected from {client_ip}.")
                    self.update_log(f"SQL Injection attempt from {client_ip}.")
                    client_socket.close()
                    return

                if password == "secure123":
                    client_socket.send("Login successful!".encode())
                    logging.info(f"Successful login from {client_ip}.")
                    self.failed_attempts[client_ip] = 0
                    self.update_log(f"Successful login from {client_ip}.")
                    client_socket.close()
                    return
                else:
                    failed_attempts += 1
                    self.failed_attempts[client_ip] = failed_attempts
                    logging.info(f"Failed login attempt from {client_ip}. Total failed attempts: {failed_attempts}")
                    self.update_log(f"Failed login attempt from {client_ip}.")
            except Exception as e:
                self.update_log(f"Error handling client {client_ip}: {e}")
                break

        self.ban_ip(client_ip, "Too many failed attempts")
        client_socket.send(b"Too many failed attempts. You are blocked.\n")
        logging.info(f"Blocked {client_ip} due to failed login attempts.")
        self.update_log(f"Blocked {client_ip} due to failed login attempts.")
        client_socket.close()

    def ban_ip(self, ip, reason):
        self.banned_ips[ip] = reason
        self.failed_attempts[ip] = self.MAX_ATTEMPTS
        logging.info(f"IP {ip} is banned due to {reason}.")
        self.update_log(f"IP {ip} is banned due to {reason}.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
