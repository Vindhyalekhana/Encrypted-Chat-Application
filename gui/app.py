import socket
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox

from cryptography.hazmat.primitives import serialization

from security.auth import validate_password
from security.message_crypto import (
    decrypt_chat_message,
    encrypt_chat_message
)
from security.network_protocol import (
    send_json,
    receive_json
)
from security.rsa_utils import (
    generate_key_pair,
    load_private_key,
    load_public_key
)

HOST = "127.0.0.1"
PORT = 5000


class EncryptedChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Chat Application")
        self.root.geometry("820x700")
        self.root.minsize(760, 620)

        self.client_socket = None
        self.username = None
        self.private_key = None

        self.active_recipient = None
        self.recipient_public_key = None

        self.receiver_thread = None
        self.running = False
        self.receiver_started = False

        self.build_login_screen()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_application
        )

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def connect_to_server(self):
        client_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        client_socket.connect(
            (HOST, PORT)
        )
        return client_socket

    def build_login_screen(self):
        self.clear_screen()
        self.root.geometry("560x650")

        main_frame = tk.Frame(
            self.root,
            padx=60,
            pady=40
        )
        main_frame.pack(
            fill="both",
            expand=True
        )

        title_label = tk.Label(
            main_frame,
            text="Encrypted Chat",
            font=("Arial", 28, "bold")
        )
        title_label.pack(
            pady=(40, 5)
        )

        subtitle_label = tk.Label(
            main_frame,
            text="Secure client-side encrypted messaging",
            font=("Arial", 11)
        )
        subtitle_label.pack(
            pady=(0, 40)
        )

        username_label = tk.Label(
            main_frame,
            text="Username",
            font=("Arial", 11, "bold")
        )
        username_label.pack(
            anchor="w"
        )

        self.username_entry = tk.Entry(
            main_frame,
            font=("Arial", 12),
            width=34
        )
        self.username_entry.pack(
            fill="x",
            pady=(6, 20),
            ipady=7
        )

        password_label = tk.Label(
            main_frame,
            text="Password",
            font=("Arial", 11, "bold")
        )
        password_label.pack(
            anchor="w"
        )

        self.password_entry = tk.Entry(
            main_frame,
            font=("Arial", 12),
            width=34,
            show="*"
        )
        self.password_entry.pack(
            fill="x",
            pady=(6, 25),
            ipady=7
        )

        login_button = tk.Button(
            main_frame,
            text="Login",
            font=("Arial", 12, "bold"),
            height=2,
            command=self.login
        )
        login_button.pack(
            fill="x",
            pady=6
        )

        register_button = tk.Button(
            main_frame,
            text="Create New Account",
            font=("Arial", 11),
            height=2,
            command=self.build_register_screen
        )
        register_button.pack(
            fill="x",
            pady=6
        )

        security_frame = tk.Frame(
            main_frame,
            pady=25
        )
        security_frame.pack()

        tk.Label(
            security_frame,
            text="AES-256-GCM",
            font=("Arial", 9, "bold")
        ).pack(
            side="left",
            padx=8
        )

        tk.Label(
            security_frame,
            text="•",
            font=("Arial", 9)
        ).pack(
            side="left"
        )

        tk.Label(
            security_frame,
            text="RSA-OAEP",
            font=("Arial", 9, "bold")
        ).pack(
            side="left",
            padx=8
        )

        tk.Label(
            security_frame,
            text="•",
            font=("Arial", 9)
        ).pack(
            side="left"
        )

        tk.Label(
            security_frame,
            text="TCP",
            font=("Arial", 9, "bold")
        ).pack(
            side="left",
            padx=8
        )

        self.username_entry.focus_set()

        self.root.bind(
            "<Return>",
            lambda event: self.login()
        )

    def build_register_screen(self):
        self.clear_screen()
        self.root.geometry("560x680")

        main_frame = tk.Frame(
            self.root,
            padx=60,
            pady=35
        )
        main_frame.pack(
            fill="both",
            expand=True
        )

        title_label = tk.Label(
            main_frame,
            text="Create Account",
            font=("Arial", 26, "bold")
        )
        title_label.pack(
            pady=(30, 5)
        )

        subtitle_label = tk.Label(
            main_frame,
            text="Create your secure chat account",
            font=("Arial", 11)
        )
        subtitle_label.pack(
            pady=(0, 35)
        )

        username_label = tk.Label(
            main_frame,
            text="Username",
            font=("Arial", 11, "bold")
        )
        username_label.pack(
            anchor="w"
        )

        self.register_username_entry = tk.Entry(
            main_frame,
            font=("Arial", 12)
        )
        self.register_username_entry.pack(
            fill="x",
            pady=(6, 20),
            ipady=7
        )

        password_label = tk.Label(
            main_frame,
            text="Password",
            font=("Arial", 11, "bold")
        )
        password_label.pack(
            anchor="w"
        )

        self.register_password_entry = tk.Entry(
            main_frame,
            font=("Arial", 12),
            show="*"
        )
        self.register_password_entry.pack(
            fill="x",
            pady=(6, 20),
            ipady=7
        )

        confirm_label = tk.Label(
            main_frame,
            text="Confirm Password",
            font=("Arial", 11, "bold")
        )
        confirm_label.pack(
            anchor="w"
        )

        self.confirm_password_entry = tk.Entry(
            main_frame,
            font=("Arial", 12),
            show="*"
        )
        self.confirm_password_entry.pack(
            fill="x",
            pady=(6, 25),
            ipady=7
        )

        register_button = tk.Button(
            main_frame,
            text="Register",
            font=("Arial", 12, "bold"),
            height=2,
            command=self.register
        )
        register_button.pack(
            fill="x",
            pady=6
        )

        back_button = tk.Button(
            main_frame,
            text="Back to Login",
            font=("Arial", 11),
            height=2,
            command=self.build_login_screen
        )
        back_button.pack(
            fill="x",
            pady=6
        )

        self.register_username_entry.focus_set()

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username:
            messagebox.showwarning(
                "Login",
                "Please enter your username."
            )
            return

        if not password:
            messagebox.showwarning(
                "Login",
                "Please enter your password."
            )
            return

        client_socket = None

        try:
            client_socket = self.connect_to_server()

            send_json(
                client_socket,
                {
                    "type": "login",
                    "username": username,
                    "password": password
                }
            )

            response = receive_json(
                client_socket
            )

            if response.get("status") != "success":
                messagebox.showerror(
                    "Login Failed",
                    response.get(
                        "message",
                        "Invalid username or password."
                    )
                )
                client_socket.close()
                return

            self.client_socket = client_socket
            self.username = response.get(
                "username"
            )

            self.prepare_user_keys(
                response
            )

            self.running = True
            self.receiver_started = False
            self.active_recipient = None
            self.recipient_public_key = None

            self.build_chat_screen()

        except (
            ConnectionError,
            OSError,
            ValueError
        ) as error:
            if client_socket:
                try:
                    client_socket.close()
                except OSError:
                    pass

            messagebox.showerror(
                "Connection Error",
                f"Could not connect to the server.\n\n{error}"
            )

    def prepare_user_keys(self, login_response):
        if not login_response.get(
            "has_public_key"
        ):
            try:
                generate_key_pair(
                    self.username
                )

                if not self.register_public_key():
                    raise ConnectionError(
                        "Failed to register RSA public key."
                    )

            except (
                FileNotFoundError,
                OSError,
                ValueError
            ) as error:
                raise ConnectionError(
                    f"RSA key setup failed: {error}"
                )

        self.private_key = load_private_key(
            self.username
        )

    def register_public_key(self):
        public_key = load_public_key(
            self.username
        )

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # The current socket is already authenticated as this user.
        send_json(
            self.client_socket,
            {
                "type": "public_key",
                "username": self.username,
                "public_key": public_key_bytes.decode(
                    "utf-8"
                )
            }
        )

        response = receive_json(
            self.client_socket
        )

        return response.get(
            "status"
        ) == "success"

    def get_recipient_public_key(
        self,
        recipient
    ):
        send_json(
            self.client_socket,
            {
                "type": "get_public_key",
                "username": recipient
            }
        )

        response = receive_json(
            self.client_socket
        )

        if response.get(
            "status"
        ) != "success":
            raise ValueError(
                response.get(
                    "message",
                    "Unable to retrieve public key."
                )
            )

        return serialization.load_pem_public_key(
            response["public_key"].encode(
                "utf-8"
            )
        )

    def build_chat_screen(self):
        self.clear_screen()
        self.root.geometry("900x720")

        main_frame = tk.Frame(
            self.root
        )
        main_frame.pack(
            fill="both",
            expand=True
        )

        header_frame = tk.Frame(
            main_frame,
            padx=25,
            pady=18
        )
        header_frame.pack(
            fill="x"
        )

        title_frame = tk.Frame(
            header_frame
        )
        title_frame.pack(
            side="left"
        )

        tk.Label(
            title_frame,
            text="Encrypted Chat",
            font=("Arial", 23, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            title_frame,
            text="Secure client-side messaging",
            font=("Arial", 9)
        ).pack(
            anchor="w",
            pady=(2, 0)
        )

        user_frame = tk.Frame(
            header_frame
        )
        user_frame.pack(
            side="right"
        )

        tk.Label(
            user_frame,
            text=f"Logged in as {self.username}",
            font=("Arial", 10, "bold")
        ).pack(
            anchor="e"
        )

        self.status_label = tk.Label(
            user_frame,
            text="● Connected",
            font=("Arial", 9)
        )
        self.status_label.pack(
            anchor="e",
            pady=(4, 0)
        )

        recipient_frame = tk.Frame(
            main_frame,
            padx=25,
            pady=10
        )
        recipient_frame.pack(
            fill="x"
        )

        tk.Label(
            recipient_frame,
            text="Chat with:",
            font=("Arial", 10, "bold")
        ).pack(
            side="left"
        )

        self.recipient_entry = tk.Entry(
            recipient_frame,
            font=("Arial", 11),
            width=25
        )
        self.recipient_entry.pack(
            side="left",
            padx=10,
            ipady=5
        )

        self.connect_button = tk.Button(
            recipient_frame,
            text="Connect",
            font=("Arial", 10, "bold"),
            width=11,
            command=self.connect_to_recipient
        )
        self.connect_button.pack(
            side="left"
        )

        chat_frame = tk.Frame(
            main_frame,
            bd=1,
            relief="solid"
        )
        chat_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=10
        )

        scrollbar = tk.Scrollbar(
            chat_frame
        )
        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.chat_text = tk.Text(
            chat_frame,
            font=("Arial", 11),
            state="disabled",
            wrap="word",
            padx=15,
            pady=15,
            yscrollcommand=scrollbar.set
        )
        self.chat_text.pack(
            fill="both",
            expand=True
        )

        scrollbar.config(
            command=self.chat_text.yview
        )

        self.chat_text.tag_configure(
            "system",
            justify="center",
            spacing1=6,
            spacing3=6
        )

        self.chat_text.tag_configure(
            "sent",
            justify="right",
            rmargin=35,
            lmargin1=180,
            lmargin2=180,
            spacing1=5,
            spacing3=5
        )

        self.chat_text.tag_configure(
            "received",
            justify="left",
            lmargin1=35,
            lmargin2=35,
            rmargin=180,
            spacing1=5,
            spacing3=5
        )

        self.chat_text.tag_configure(
            "sent_header",
            justify="right",
            rmargin=35,
            lmargin1=180,
            lmargin2=180,
            spacing1=8,
            spacing3=1
        )

        self.chat_text.tag_configure(
            "received_header",
            justify="left",
            lmargin1=35,
            lmargin2=35,
            rmargin=180,
            spacing1=8,
            spacing3=1
        )

        input_frame = tk.Frame(
            main_frame,
            padx=25,
            pady=10
        )
        input_frame.pack(
            fill="x"
        )

        self.message_entry = tk.Entry(
            input_frame,
            font=("Arial", 11)
        )
        self.message_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=9
        )

        self.send_button = tk.Button(
            input_frame,
            text="Send",
            font=("Arial", 10, "bold"),
            width=12,
            height=2,
            command=self.send_message
        )
        self.send_button.pack(
            side="left",
            padx=(10, 0)
        )

        self.message_entry.bind(
            "<Return>",
            lambda event: self.send_message()
        )

        bottom_frame = tk.Frame(
            main_frame,
            padx=25,
            pady=12
        )
        bottom_frame.pack(
            fill="x"
        )

        tk.Label(
            bottom_frame,
            text="🔒 AES-256-GCM  +  RSA-OAEP",
            font=("Arial", 9, "bold")
        ).pack(
            side="left"
        )

        tk.Button(
            bottom_frame,
            text="Logout",
            width=10,
            command=self.logout
        ).pack(
            side="right"
        )

        self.add_system_message(
            "Secure chat connection established."
        )

        self.add_system_message(
            "Enter a recipient username and click Connect."
        )

        self.message_entry.focus_set()

    def connect_to_recipient(self):
        if not self.running:
            return

        if self.receiver_started:
            messagebox.showinfo(
                "Chat",
                "This chat session is already connected."
            )
            return

        recipient = self.recipient_entry.get().strip()

        if not recipient:
            messagebox.showwarning(
                "Recipient",
                "Please enter a recipient username."
            )
            return

        if recipient == self.username:
            messagebox.showwarning(
                "Recipient",
                "You cannot chat with yourself."
            )
            return

        try:
            self.status_label.config(
                text="● Retrieving public key..."
            )

            self.connect_button.config(
                state="disabled"
            )

            self.root.update_idletasks()

            recipient_public_key = (
                self.get_recipient_public_key(
                    recipient
                )
            )

            self.active_recipient = recipient
            self.recipient_public_key = (
                recipient_public_key
            )

            self.status_label.config(
                text=f"● Secure chat with {recipient}"
            )

            self.add_system_message(
                f"Secure connection established with {recipient}."
            )

            self.receiver_started = True

            self.receiver_thread = threading.Thread(
                target=self.receive_messages,
                daemon=True
            )
            self.receiver_thread.start()

        except (
            ConnectionError,
            OSError,
            ValueError
        ) as error:
            self.connect_button.config(
                state="normal"
            )

            self.status_label.config(
                text="● Connected"
            )

            messagebox.showerror(
                "Connection Failed",
                str(error)
            )

    def send_message(self):
        if not self.running:
            return

        if not self.client_socket:
            return

        if not self.active_recipient:
            messagebox.showwarning(
                "Message",
                "Connect to a recipient before sending."
            )
            return

        message = self.message_entry.get()

        if not message.strip():
            return

        try:
            encrypted_packet = encrypt_chat_message(
                message,
                self.recipient_public_key
            )

            encrypted_packet.update(
                {
                    "type": "encrypted_message",
                    "sender": self.username,
                    "recipient": self.active_recipient
                }
            )

            send_json(
                self.client_socket,
                encrypted_packet
            )

            self.add_chat_message(
                "You",
                message,
                sent=True
            )

            self.message_entry.delete(
                0,
                "end"
            )

        except (
            ConnectionError,
            OSError,
            ValueError
        ) as error:
            messagebox.showerror(
                "Send Failed",
                str(error)
            )

    def receive_messages(self):
        while (
            self.running
            and self.client_socket
        ):
            try:
                message = receive_json(
                    self.client_socket
                )

                if message.get(
                    "type"
                ) != "encrypted_message":
                    continue

                decrypted_message = (
                    decrypt_chat_message(
                        message["encrypted_key"],
                        message["nonce"],
                        message["ciphertext"],
                        self.private_key
                    )
                )

                sender = message.get(
                    "sender",
                    "Unknown"
                )

                self.root.after(
                    0,
                    self.add_chat_message,
                    sender,
                    decrypted_message,
                    False
                )

            except ConnectionError:
                if self.running:
                    self.root.after(
                        0,
                        self.handle_connection_closed
                    )
                break

            except (
                ValueError,
                OSError
            ):
                if self.running:
                    self.root.after(
                        0,
                        self.add_system_message,
                        "Failed to process an incoming message."
                    )
                break

            except Exception:
                if self.running:
                    self.root.after(
                        0,
                        self.add_system_message,
                        "Failed to decrypt an incoming message."
                    )
                break

    def add_system_message(self, message):
        if not hasattr(
            self,
            "chat_text"
        ):
            return

        timestamp = datetime.now().strftime(
            "%H:%M"
        )

        self.chat_text.config(
            state="normal"
        )

        self.chat_text.insert(
            "end",
            f"\n{message}  [{timestamp}]\n",
            "system"
        )

        self.chat_text.config(
            state="disabled"
        )

        self.chat_text.see(
            "end"
        )

    def add_chat_message(
        self,
        sender,
        message,
        sent=False
    ):
        if not hasattr(
            self,
            "chat_text"
        ):
            return

        timestamp = datetime.now().strftime(
            "%H:%M"
        )

        self.chat_text.config(
            state="normal"
        )

        if sent:
            header_tag = "sent_header"
            message_tag = "sent"
        else:
            header_tag = "received_header"
            message_tag = "received"

        self.chat_text.insert(
            "end",
            f"\n{sender}  [{timestamp}]\n",
            header_tag
        )

        self.chat_text.insert(
            "end",
            f"{message}\n",
            message_tag
        )

        self.chat_text.config(
            state="disabled"
        )

        self.chat_text.see(
            "end"
        )

    def handle_connection_closed(self):
        self.running = False

        if hasattr(
            self,
            "status_label"
        ):
            self.status_label.config(
                text="● Server connection closed"
            )

        if hasattr(
            self,
            "chat_text"
        ):
            self.add_system_message(
                "Server connection closed."
            )

    def logout(self):
        self.running = False
        self.receiver_started = False

        if self.client_socket:
            try:
                self.client_socket.shutdown(
                    socket.SHUT_RDWR
                )
            except OSError:
                pass

            try:
                self.client_socket.close()
            except OSError:
                pass

        self.client_socket = None
        self.username = None
        self.private_key = None
        self.active_recipient = None
        self.recipient_public_key = None

        self.build_login_screen()

    def close_application(self):
        self.running = False

        if self.client_socket:
            try:
                self.client_socket.shutdown(
                    socket.SHUT_RDWR
                )
            except OSError:
                pass

            try:
                self.client_socket.close()
            except OSError:
                pass

        self.root.destroy()

    def register(self):
        username = self.register_username_entry.get().strip()
        password = self.register_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not username:
            messagebox.showwarning(
                "Registration",
                "Please enter a username."
            )
            return

        if not validate_password(password):
            messagebox.showwarning(
                "Registration",
                "Password must be at least 8 characters long."
            )
            return

        if password != confirm_password:
            messagebox.showwarning(
                "Registration",
                "Passwords do not match."
            )
            return

        client_socket = None

        try:
            client_socket = self.connect_to_server()

            send_json(
                client_socket,
                {
                    "type": "register",
                    "username": username,
                    "password": password
                }
            )

            response = receive_json(
                client_socket
            )

            if response.get(
                "status"
            ) != "success":
                messagebox.showerror(
                    "Registration Failed",
                    response.get(
                        "message",
                        "Registration failed."
                    )
                )
                return

            messagebox.showinfo(
                "Registration Successful",
                "Account created successfully.\n\n"
                "An RSA key pair will be generated "
                "when you log in."
            )

            self.build_login_screen()

        except (
            ConnectionError,
            OSError,
            ValueError
        ) as error:
            messagebox.showerror(
                "Connection Error",
                f"Could not connect to the server.\n\n{error}"
            )

        finally:
            if client_socket:
                client_socket.close()


def main():
    root = tk.Tk()

    EncryptedChatApp(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    main()