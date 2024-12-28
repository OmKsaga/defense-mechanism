import socket
import tkinter as tk
from tkinter import messagebox

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Client Application")
        self.root.geometry("400x300")
        self.root.configure(bg="#f5f5f5")

        self.client_socket = None
        self.is_connected = False
        self.is_banned = False
        self.remaining_attempts = 3

        self.create_widgets()

    def create_widgets(self):
        self.connection_status = tk.Label(
            self.root, text="Status: Not Connected", font=("Arial", 12), bg="#f5f5f5", fg="red"
        )
        self.connection_status.pack(pady=10)

        self.connect_button = tk.Button(
            self.root, text="Connect to Server", font=("Arial", 12, "bold"), bg="#4caf50", fg="white",
            activebackground="#45a049", activeforeground="white", width=20, command=self.connect_to_server
        )
        self.connect_button.pack(pady=10)

        self.password_label = tk.Label(self.root, text="Enter Password:", font=("Arial", 12), bg="#f5f5f5")
        self.password_label.pack(pady=10)

        self.password_entry = tk.Entry(self.root, font=("Arial", 12), width=25, show="*")
        self.password_entry.pack(pady=5)

        self.send_button = tk.Button(
            self.root, text="Send Password", font=("Arial", 12, "bold"), bg="#2196f3", fg="white",
            activebackground="#1976d2", activeforeground="white", width=20, command=self.send_password
        )
        self.send_button.pack(pady=10)

        self.quit_button = tk.Button(
            self.root, text="Quit", font=("Arial", 12, "bold"), bg="#f44336", fg="white",
            activebackground="#e53935", activeforeground="white", width=20, command=self.quit_app
        )
        self.quit_button.pack(pady=10)

    def connect_to_server(self):
        if self.is_connected:
            messagebox.showinfo("Connection Info", "You are already connected to the server.")
            return

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(("127.0.0.1", 9999))  # Change IP and port as needed
            self.is_connected = True
            self.connection_status.config(text="Status: Connected", fg="green")
            self.connect_button.config(state=tk.DISABLED)
            messagebox.showinfo("Connection Info", "Successfully connected to the server.")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")

    def send_password(self):
        if not self.is_connected:
            messagebox.showerror("Connection Error", "You are not connected to the server.")
            return

        if self.is_banned:
            messagebox.showwarning("Banned", "You are banned from the server.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return

        try:
            self.client_socket.send(password.encode())
            response = self.client_socket.recv(1024).decode('utf-8').strip()

            # Debugging: Log the exact response for clarity
            print(f"Server Response: '{response}'")  # Ensure no hidden characters

            if response == "Login successful!":
                messagebox.showinfo("Success", response)
                self.root.configure(bg="#4caf50")  # Change background to green
                self.password_entry.config(state=tk.DISABLED)
                self.send_button.config(state=tk.DISABLED)
            elif "SQL Injection" in response or "banned" in response:
                self.is_banned = True
                messagebox.showerror("Security Alert", response)
                self.disconnect()
            else:
                self.remaining_attempts -= 1
                messagebox.showwarning("Login Failed", f"{response}\nRemaining attempts: {self.remaining_attempts}")
                if self.remaining_attempts <= 0:
                    self.is_banned = True
                    messagebox.showerror("Blocked", "You have been blocked from the server.")
                    self.disconnect()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to send password: {e}")

    def disconnect(self):
        if self.client_socket:
            self.client_socket.close()
        self.is_connected = False
        self.connection_status.config(text="Status: Not Connected", fg="red")
        self.connect_button.config(state=tk.NORMAL)

    def quit_app(self):
        if self.is_connected:
            self.disconnect()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
