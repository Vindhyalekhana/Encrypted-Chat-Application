import socket
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox
from cryptography.hazmat.primitives import serialization
from database.message_history import derive_history_key, initialize_history_database, load_all_conversations, save_message
from security.auth import validate_password
from security.message_crypto import encrypt_chat_message, decrypt_chat_message
from security.network_protocol import send_json, receive_json, create_request
from security.rsa_utils import generate_key_pair, load_private_key, load_public_key
HOST = '127.0.0.1'
PORT = 5000
REQUEST_TIMEOUT = 15

class EncryptedChatApp:

    def __init__(self, root):
        self.root = root
        self.root.title('Encrypted Chat')
        self.root.geometry('1100x720')
        self.root.minsize(900, 600)
        self.root.protocol('WM_DELETE_WINDOW', self.close_application)
        self.client_socket = None
        self.username = None
        self.private_key = None
        self.history_key = None
        self.running = False
        self.receiver_started = False
        self.receiver_thread = None
        self.active_recipient = None
        self.recipient_public_keys = {}
        self.conversations = {}
        self.unread_counts = {}
        self.online_status = {}
        self.pending_requests = {}
        self.pending_requests_lock = threading.Lock()
        self.socket_send_lock = threading.Lock()
        self.dark_mode = False
        self.colors = {}
        self.root.bind('<Return>', self.handle_return_key)
        self.build_login_screen()

    def close_application(self):
        self.running = False
        if hasattr(self, 'fail_pending_requests'):
            self.fail_pending_requests('Application closed.')
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.client_socket.close()
            except OSError:
                pass
            self.client_socket = None
        self.root.destroy()

    def update_colors(self):
        if self.dark_mode:
            self.colors = {'bg': '#17202A', 'sidebar': '#111820', 'header': '#1F2A35', 'chat': '#17202A', 'input': '#202B36', 'border': '#34495E', 'text': '#ECF0F1', 'muted': '#AAB7B8', 'accent': '#3498DB', 'accent_dark': '#2980B9', 'sent': '#1F618D', 'received': '#273746', 'online': '#2ECC71', 'danger': '#E74C3C', 'white': '#FFFFFF'}
        else:
            self.colors = {'bg': '#F5F7FA', 'sidebar': '#FFFFFF', 'header': '#FFFFFF', 'chat': '#F5F7FA', 'input': '#FFFFFF', 'border': '#D5DBDB', 'text': '#17202A', 'muted': '#7F8C8D', 'accent': '#3498DB', 'accent_dark': '#2980B9', 'sent': '#D6EAF8', 'received': '#FFFFFF', 'online': '#27AE60', 'danger': '#E74C3C', 'white': '#FFFFFF'}

    def apply_root_background(self):
        self.root.configure(bg=self.colors['bg'])

    def handle_return_key(self, event):
        if hasattr(self, 'message_entry'):
            self.send_message()
        elif hasattr(self, 'username_entry'):
            self.login()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def connect_to_server(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        return client_socket

    def build_login_screen(self):
        self.update_colors()
        self.apply_root_background()
        self.clear_screen()
        self.root.geometry('560x680')
        main_frame = tk.Frame(self.root, bg=self.colors['bg'], padx=65, pady=40)
        main_frame.pack(fill='both', expand=True)
        tk.Label(main_frame, text='🔐', font=('Arial', 34), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(25, 5))
        tk.Label(main_frame, text='Encrypted Chat', font=('Arial', 28, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(pady=(0, 5))
        tk.Label(main_frame, text='Secure client-side messaging', font=('Arial', 11), bg=self.colors['bg'], fg=self.colors['muted']).pack(pady=(0, 35))
        self.create_login_field(main_frame, 'Username')
        self.username_entry = self.login_username_entry
        self.create_password_field(main_frame, 'Password')
        login_button = tk.Button(main_frame, text='Sign In', font=('Arial', 11, 'bold'), bg=self.colors['accent'], fg='white', activebackground=self.colors['accent_dark'], activeforeground='white', relief='flat', cursor='hand2', command=self.login)
        login_button.pack(fill='x', ipady=8, pady=(5, 10))
        register_button = tk.Button(main_frame, text='Create New Account', font=('Arial', 10), bg=self.colors['bg'], fg=self.colors['accent'], activebackground=self.colors['bg'], activeforeground=self.colors['accent_dark'], relief='flat', cursor='hand2', command=self.build_register_screen)
        register_button.pack(pady=5)
        security_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        security_frame.pack(pady=30)
        tk.Label(security_frame, text='AES-256-GCM', font=('Arial', 9, 'bold'), bg=self.colors['bg'], fg=self.colors['muted']).pack(side='left')
        tk.Label(security_frame, text='  •  ', bg=self.colors['bg'], fg=self.colors['muted']).pack(side='left')
        tk.Label(security_frame, text='RSA-OAEP', font=('Arial', 9, 'bold'), bg=self.colors['bg'], fg=self.colors['muted']).pack(side='left')
        tk.Label(security_frame, text='  •  ', bg=self.colors['bg'], fg=self.colors['muted']).pack(side='left')
        tk.Label(security_frame, text='TCP', font=('Arial', 9, 'bold'), bg=self.colors['bg'], fg=self.colors['muted']).pack(side='left')
        self.login_username_entry.focus_set()

    def create_login_field(self, parent, label):
        tk.Label(parent, text=label, font=('Arial', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(anchor='w')
        self.login_username_entry = tk.Entry(parent, font=('Arial', 12), bg=self.colors['input'], fg=self.colors['text'], relief='solid', bd=1)
        self.login_username_entry.pack(fill='x', ipady=8, pady=(6, 18))

    def create_password_field(self, parent, label):
        tk.Label(parent, text=label, font=('Arial', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(anchor='w')
        self.password_entry = tk.Entry(parent, font=('Arial', 12), show='*', bg=self.colors['input'], fg=self.colors['text'], relief='solid', bd=1)
        self.password_entry.pack(fill='x', ipady=8, pady=(6, 25))

    def build_register_screen(self):
        self.update_colors()
        self.apply_root_background()
        self.clear_screen()
        self.root.geometry('560x700')
        main_frame = tk.Frame(self.root, bg=self.colors['bg'], padx=65, pady=35)
        main_frame.pack(fill='both', expand=True)
        tk.Label(main_frame, text='Create Account', font=('Arial', 27, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(pady=(25, 5))
        tk.Label(main_frame, text='Create your secure chat identity', font=('Arial', 11), bg=self.colors['bg'], fg=self.colors['muted']).pack(pady=(0, 30))
        tk.Label(main_frame, text='Username', font=('Arial', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(anchor='w')
        self.register_username_entry = tk.Entry(main_frame, font=('Arial', 12), bg=self.colors['input'], fg=self.colors['text'], relief='solid', bd=1)
        self.register_username_entry.pack(fill='x', ipady=8, pady=(6, 18))
        tk.Label(main_frame, text='Password', font=('Arial', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(anchor='w')
        self.register_password_entry = tk.Entry(main_frame, font=('Arial', 12), show='*', bg=self.colors['input'], fg=self.colors['text'], relief='solid', bd=1)
        self.register_password_entry.pack(fill='x', ipady=8, pady=(6, 18))
        tk.Label(main_frame, text='Confirm Password', font=('Arial', 10, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(anchor='w')
        self.confirm_password_entry = tk.Entry(main_frame, font=('Arial', 12), show='*', bg=self.colors['input'], fg=self.colors['text'], relief='solid', bd=1)
        self.confirm_password_entry.pack(fill='x', ipady=8, pady=(6, 25))
        tk.Button(main_frame, text='Create Account', font=('Arial', 11, 'bold'), bg=self.colors['accent'], fg='white', activebackground=self.colors['accent_dark'], activeforeground='white', relief='flat', cursor='hand2', command=self.register).pack(fill='x', ipady=8, pady=5)
        tk.Button(main_frame, text='Back to Login', font=('Arial', 10), bg=self.colors['bg'], fg=self.colors['accent'], relief='flat', cursor='hand2', command=self.build_login_screen).pack(pady=8)
        self.register_username_entry.focus_set()

    def login(self):
        username = self.login_username_entry.get().strip()
        password = self.password_entry.get()
        if not username:
            messagebox.showwarning('Login', 'Please enter your username.')
            return
        if not password:
            messagebox.showwarning('Login', 'Please enter your password.')
            return
        client_socket = None
        try:
            client_socket = self.connect_to_server()
            request = create_request('login', username=username, password=password)
            send_json(client_socket, request)
            response = receive_json(client_socket)
            if response.get('status') != 'success':
                messagebox.showerror('Login Failed', response.get('message', 'Invalid username or password.'))
                client_socket.close()
                return
            self.client_socket = client_socket
            self.username = response.get('username')
            self.running = True
            self.start_receiver()
            self.prepare_user_keys(response)
            self.history_key = derive_history_key(self.username, password)
            initialize_history_database()
            self.conversations = load_all_conversations(self.username, self.history_key)
            self.unread_counts = {}
            self.recipient_public_keys = {}
            self.build_chat_screen()
            self.refresh_user_status()
        except (ConnectionError, OSError, ValueError, TimeoutError) as error:
            self.running = False
            if client_socket:
                try:
                    client_socket.close()
                except OSError:
                    pass
            self.client_socket = None
            messagebox.showerror('Connection Error', f'Could not connect to the server.\n\n{error}')

    def prepare_user_keys(self, login_response):
        if not login_response.get('has_public_key'):
            try:
                generate_key_pair(self.username)
                if not self.register_public_key():
                    raise ConnectionError('Failed to register RSA public key.')
            except (FileNotFoundError, OSError, ValueError, ConnectionError) as error:
                raise ConnectionError(f'RSA key setup failed: {error}')
        self.private_key = load_private_key(self.username)

    def register_public_key(self):
        public_key = load_public_key(self.username)
        public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        response = self.send_request('public_key', username=self.username, public_key=public_key_bytes.decode('utf-8'))
        return response.get('status') == 'success'

    def send_request(self, request_type, **data):
        request = create_request(request_type, **data)
        request_id = request['request_id']
        event = threading.Event()
        with self.pending_requests_lock:
            self.pending_requests[request_id] = {'event': event, 'response': None}
        try:
            with self.socket_send_lock:
                send_json(self.client_socket, request)
            if not event.wait(REQUEST_TIMEOUT):
                raise TimeoutError('Server response timed out.')
            with self.pending_requests_lock:
                pending = self.pending_requests.get(request_id)
                if not pending:
                    raise ConnectionError('Response was lost.')
                return pending['response']
        finally:
            with self.pending_requests_lock:
                self.pending_requests.pop(request_id, None)

    def start_receiver(self):
        if self.receiver_started:
            return
        self.receiver_started = True
        self.receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receiver_thread.start()

    def refresh_user_status(self):
        if not self.running:
            return
        try:
            response = self.send_request('list_users')
            if response.get('status') == 'success':
                self.online_status = {user['username']: user['online'] for user in response.get('users', [])}
                for user in response.get('users', []):
                    username = user['username']
                    if username in self.conversations and username not in self.unread_counts:
                        self.unread_counts[username] = 0
                if hasattr(self, 'conversation_list'):
                    self.refresh_conversation_list()
                if self.active_recipient:
                    self.update_chat_header_status()
        except (ConnectionError, OSError, ValueError, TimeoutError):
            pass
        if self.running:
            self.root.after(5000, self.refresh_user_status)

    def update_chat_header_status(self):
        if not self.active_recipient:
            return
        is_online = self.online_status.get(self.active_recipient, False)
        if is_online:
            self.chat_status.config(text='● Online  •  Secure session', fg=self.colors['online'])
        else:
            self.chat_status.config(text='○ Offline  •  Secure session', fg=self.colors['muted'])

    def build_chat_screen(self):
        self.update_colors()
        self.apply_root_background()
        self.clear_screen()
        self.root.geometry('1150x750')
        main_frame = tk.Frame(self.root, bg=self.colors['bg'])
        main_frame.pack(fill='both', expand=True)
        self.build_sidebar(main_frame)
        self.build_chat_area(main_frame)
        self.show_empty_chat()

    def build_sidebar(self, parent):
        self.sidebar = tk.Frame(parent, bg=self.colors['sidebar'], width=290)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)
        header = tk.Frame(self.sidebar, bg=self.colors['sidebar'], padx=20, pady=20)
        header.pack(fill='x')
        tk.Label(header, text='Encrypted Chat', font=('Arial', 19, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text']).pack(anchor='w')
        tk.Label(header, text='Secure messaging', font=('Arial', 9), bg=self.colors['sidebar'], fg=self.colors['muted']).pack(anchor='w', pady=(3, 0))
        search_frame = tk.Frame(self.sidebar, bg=self.colors['sidebar'], padx=15, pady=5)
        search_frame.pack(fill='x')
        self.search_entry = tk.Entry(search_frame, font=('Arial', 10), bg=self.colors['input'], fg=self.colors['text'], relief='solid', bd=1)
        self.search_entry.pack(fill='x', ipady=6)
        self.search_entry.insert(0, 'Search chats...')
        self.search_entry.config(fg=self.colors['muted'])
        self.search_entry.bind('<FocusIn>', self.clear_search_placeholder)
        self.search_entry.bind('<KeyRelease>', self.filter_conversations)
        action_frame = tk.Frame(self.sidebar, bg=self.colors['sidebar'], padx=15, pady=12)
        action_frame.pack(fill='x')
        tk.Button(action_frame, text='+  New Chat', font=('Arial', 10, 'bold'), bg=self.colors['accent'], fg='white', activebackground=self.colors['accent_dark'], activeforeground='white', relief='flat', cursor='hand2', command=self.new_chat).pack(fill='x', ipady=6)
        tk.Label(self.sidebar, text='CONVERSATIONS', font=('Arial', 8, 'bold'), bg=self.colors['sidebar'], fg=self.colors['muted']).pack(anchor='w', padx=20, pady=(8, 6))
        self.conversation_list = tk.Frame(self.sidebar, bg=self.colors['sidebar'])
        self.conversation_list.pack(fill='both', expand=True, padx=8)
        bottom = tk.Frame(self.sidebar, bg=self.colors['sidebar'], padx=15, pady=15)
        bottom.pack(fill='x')
        self.theme_button = tk.Button(bottom, text='🌙 Dark Mode', font=('Arial', 9), bg=self.colors['sidebar'], fg=self.colors['text'], activebackground=self.colors['border'], activeforeground=self.colors['text'], relief='flat', cursor='hand2', command=self.toggle_theme)
        self.theme_button.pack(fill='x', pady=3)
        tk.Button(bottom, text=f'👤  {self.username}', font=('Arial', 9, 'bold'), bg=self.colors['sidebar'], fg=self.colors['text'], activebackground=self.colors['border'], activeforeground=self.colors['text'], relief='flat', anchor='w', cursor='hand2', command=self.show_profile).pack(fill='x', pady=3)
        tk.Button(bottom, text='↪  Logout', font=('Arial', 9), bg=self.colors['sidebar'], fg=self.colors['danger'], activebackground=self.colors['border'], activeforeground=self.colors['danger'], relief='flat', anchor='w', cursor='hand2', command=self.logout).pack(fill='x', pady=3)

    def refresh_conversation_list(self):
        if not hasattr(self, 'conversation_list'):
            return
        for widget in self.conversation_list.winfo_children():
            widget.destroy()
        search = ''
        if hasattr(self, 'search_entry'):
            search = self.search_entry.get().strip().lower()
            if search == 'search chats...':
                search = ''
        for username in self.conversations:
            if search and search not in username.lower():
                continue
            unread = self.unread_counts.get(username, 0)
            active = username == self.active_recipient
            background = self.colors['received'] if active else self.colors['sidebar']
            is_online = self.online_status.get(username, False)
            button_frame = tk.Frame(self.conversation_list, bg=background, cursor='hand2')
            button_frame.pack(fill='x', pady=2)
            avatar = tk.Label(button_frame, text=username[0].upper(), font=('Arial', 12, 'bold'), width=3, height=2, bg=self.colors['accent'], fg='white')
            avatar.pack(side='left', padx=(6, 8), pady=5)
            text_frame = tk.Frame(button_frame, bg=background)
            text_frame.pack(side='left', fill='both', expand=True, pady=5)
            name_frame = tk.Frame(text_frame, bg=background)
            name_frame.pack(fill='x')
            tk.Label(name_frame, text=username, font=('Arial', 10, 'bold'), bg=background, fg=self.colors['text']).pack(side='left')
            status_text = '● Online' if is_online else '○ Offline'
            status_color = self.colors['online'] if is_online else self.colors['muted']
            tk.Label(name_frame, text=status_text, font=('Arial', 7, 'bold'), bg=background, fg=status_color).pack(side='right', padx=(5, 4))
            last_message = ''
            if self.conversations.get(username):
                last_message = self.conversations[username][-1]['message']
            if len(last_message) > 27:
                last_message = last_message[:27] + '...'
            tk.Label(text_frame, text=last_message, font=('Arial', 8), bg=background, fg=self.colors['muted']).pack(anchor='w')
            if unread:
                tk.Label(button_frame, text=str(unread), font=('Arial', 8, 'bold'), bg=self.colors['accent'], fg='white', width=2).pack(side='right', padx=8)
            for widget in (button_frame, avatar, text_frame, name_frame):
                widget.bind('<Button-1>', lambda event, name=username: self.select_conversation(name))

    def clear_search_placeholder(self, event=None):
        if self.search_entry.get() == 'Search chats...':
            self.search_entry.delete(0, 'end')
            self.search_entry.config(fg=self.colors['text'])

    def filter_conversations(self, event=None):
        self.refresh_conversation_list()

    def build_chat_area(self, parent):
        self.chat_area = tk.Frame(parent, bg=self.colors['chat'])
        self.chat_area.pack(side='left', fill='both', expand=True)
        self.chat_header = tk.Frame(self.chat_area, bg=self.colors['header'], height=78)
        self.chat_header.pack(fill='x')
        self.chat_header.pack_propagate(False)
        self.chat_header_content = tk.Frame(self.chat_header, bg=self.colors['header'], padx=22)
        self.chat_header_content.pack(fill='both', expand=True)
        self.chat_title = tk.Label(self.chat_header_content, text='Select a conversation', font=('Arial', 16, 'bold'), bg=self.colors['header'], fg=self.colors['text'])
        self.chat_title.pack(side='left', anchor='center')
        self.chat_status = tk.Label(self.chat_header_content, text='', font=('Arial', 9), bg=self.colors['header'], fg=self.colors['muted'])
        self.chat_status.pack(side='left', padx=12)
        self.security_status = tk.Label(self.chat_header_content, text='🔐 Encrypted', font=('Arial', 9, 'bold'), bg=self.colors['header'], fg=self.colors['online'])
        self.security_status.pack(side='right')
        self.messages_frame = tk.Frame(self.chat_area, bg=self.colors['chat'])
        self.messages_frame.pack(fill='both', expand=True)
        self.message_canvas = tk.Canvas(self.messages_frame, bg=self.colors['chat'], highlightthickness=0)
        self.message_scrollbar = tk.Scrollbar(self.messages_frame, command=self.message_canvas.yview)
        self.message_canvas.configure(yscrollcommand=self.message_scrollbar.set)
        self.message_scrollbar.pack(side='right', fill='y')
        self.message_canvas.pack(side='left', fill='both', expand=True)
        self.message_container = tk.Frame(self.message_canvas, bg=self.colors['chat'])
        self.message_window = self.message_canvas.create_window((0, 0), window=self.message_container, anchor='nw')
        self.message_container.bind('<Configure>', self.update_message_scroll_region)
        self.message_canvas.bind('<Configure>', self.resize_message_container)
        input_outer = tk.Frame(self.chat_area, bg=self.colors['header'], padx=18, pady=15)
        input_outer.pack(fill='x')
        self.message_entry = tk.Entry(input_outer, font=('Arial', 11), bg=self.colors['input'], fg=self.colors['text'], relief='solid', bd=1)
        self.message_entry.pack(side='left', fill='x', expand=True, ipady=10)
        self.message_entry.bind('<Return>', lambda event: self.send_message())
        self.send_button = tk.Button(input_outer, text='➤', font=('Arial', 13, 'bold'), width=5, bg=self.colors['accent'], fg='white', activebackground=self.colors['accent_dark'], activeforeground='white', relief='flat', cursor='hand2', command=self.send_message)
        self.send_button.pack(side='left', padx=(10, 0), ipady=4)

    def update_message_scroll_region(self, event=None):
        self.message_canvas.configure(scrollregion=self.message_canvas.bbox('all'))
        self.message_canvas.yview_moveto(1)

    def resize_message_container(self, event):
        self.message_canvas.itemconfigure(self.message_window, width=event.width)

    def new_chat(self):
        dialog = tk.Toplevel(self.root)
        dialog.title('New Chat')
        dialog.geometry('400x230')
        dialog.resizable(False, False)
        dialog.configure(bg=self.colors['bg'])
        tk.Label(dialog, text='Start a New Chat', font=('Arial', 17, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack(pady=(25, 8))
        tk.Label(dialog, text="Enter the recipient's username", font=('Arial', 10), bg=self.colors['bg'], fg=self.colors['muted']).pack()
        username_entry = tk.Entry(dialog, font=('Arial', 12), bg=self.colors['input'], fg=self.colors['text'])
        username_entry.pack(fill='x', padx=45, pady=18, ipady=7)

        def start_chat():
            recipient = username_entry.get().strip()
            if not recipient:
                messagebox.showwarning('New Chat', 'Please enter a username.', parent=dialog)
                return
            if recipient == self.username:
                messagebox.showwarning('New Chat', 'You cannot chat with yourself.', parent=dialog)
                return
            try:
                public_key = self.get_recipient_public_key(recipient)
                self.recipient_public_keys[recipient] = public_key
                if recipient not in self.conversations:
                    self.conversations[recipient] = []
                self.unread_counts[recipient] = 0
                dialog.destroy()
                self.select_conversation(recipient)
            except (ConnectionError, OSError, ValueError, TimeoutError) as error:
                messagebox.showerror('Unable to Start Chat', str(error), parent=dialog)
        tk.Button(dialog, text='Start Chat', font=('Arial', 10, 'bold'), bg=self.colors['accent'], fg='white', relief='flat', cursor='hand2', command=start_chat).pack(ipadx=20, ipady=7)
        username_entry.focus_set()

    def select_conversation(self, recipient):
        if recipient not in self.conversations:
            self.conversations[recipient] = []
        if recipient not in self.recipient_public_keys:
            try:
                self.recipient_public_keys[recipient] = self.get_recipient_public_key(recipient)
            except (ConnectionError, OSError, ValueError, TimeoutError) as error:
                messagebox.showerror('Connection Failed', str(error))
                return
        self.active_recipient = recipient
        self.unread_counts[recipient] = 0
        self.chat_title.config(text=recipient)
        self.update_chat_header_status()
        self.security_status.config(text='🔐 AES-256-GCM')
        self.render_conversation()
        self.refresh_conversation_list()
        self.message_entry.focus_set()

    def get_recipient_public_key(self, recipient):
        response = self.send_request('get_public_key', username=recipient)
        if response.get('status') != 'success':
            raise ValueError(response.get('message', 'Unable to retrieve public key.'))
        return serialization.load_pem_public_key(response['public_key'].encode('utf-8'))

    def render_conversation(self):
        for widget in self.message_container.winfo_children():
            widget.destroy()
        if not self.active_recipient:
            return
        messages = self.conversations.get(self.active_recipient, [])
        if not messages:
            self.show_chat_welcome()
            return
        for message in messages:
            self.create_message_bubble(message['sender'], message['message'], message['time'], message['sent'])
        self.root.after(50, lambda: self.message_canvas.yview_moveto(1))

    def show_chat_welcome(self):
        frame = tk.Frame(self.message_container, bg=self.colors['chat'])
        frame.pack(fill='both', expand=True, pady=100)
        tk.Label(frame, text='🔐', font=('Arial', 35), bg=self.colors['chat'], fg=self.colors['accent']).pack()
        tk.Label(frame, text=f'Secure conversation with {self.active_recipient}', font=('Arial', 15, 'bold'), bg=self.colors['chat'], fg=self.colors['text']).pack(pady=(12, 5))
        tk.Label(frame, text='Messages are encrypted using AES-256-GCM\nwith RSA-OAEP protected session keys.', font=('Arial', 9), bg=self.colors['chat'], fg=self.colors['muted'], justify='center').pack()

    def create_message_bubble(self, sender, message, timestamp, sent):
        row = tk.Frame(self.message_container, bg=self.colors['chat'])
        row.pack(fill='x', padx=18, pady=5)
        bubble = tk.Frame(row, bg=self.colors['sent'] if sent else self.colors['received'], padx=12, pady=8)
        if sent:
            bubble.pack(side='right', anchor='e')
        else:
            bubble.pack(side='left', anchor='w')
        header = tk.Label(bubble, text='You' if sent else sender, font=('Arial', 8, 'bold'), bg=bubble['bg'], fg=self.colors['accent'] if sent else self.colors['text'])
        header.pack(anchor='w')
        tk.Label(bubble, text=message, font=('Arial', 10), bg=bubble['bg'], fg=self.colors['text'], wraplength=450, justify='left').pack(anchor='w', pady=(3, 3))
        tk.Label(bubble, text=timestamp, font=('Arial', 7), bg=bubble['bg'], fg=self.colors['muted']).pack(anchor='e')

    def send_message(self):
        if not self.running:
            return
        if not self.client_socket:
            return
        if not self.active_recipient:
            messagebox.showwarning('Message', 'Select or create a conversation first.')
            return
        message = self.message_entry.get()
        if not message.strip():
            return
        try:
            recipient_key = self.recipient_public_keys.get(self.active_recipient)
            if not recipient_key:
                recipient_key = self.get_recipient_public_key(self.active_recipient)
                self.recipient_public_keys[self.active_recipient] = recipient_key
            encrypted_packet = encrypt_chat_message(message, recipient_key)
            response = self.send_request('encrypted_message', sender=self.username, recipient=self.active_recipient, encrypted_key=encrypted_packet['encrypted_key'], nonce=encrypted_packet['nonce'], ciphertext=encrypted_packet['ciphertext'])
            if response.get('status') != 'success':
                raise ValueError(response.get('message', 'Message delivery failed.'))
            timestamp = datetime.now().strftime('%H:%M')
            self.conversations.setdefault(self.active_recipient, []).append({'sender': self.username, 'message': message, 'time': timestamp, 'sent': True})
            save_message(self.username, self.active_recipient, self.username, message, True, datetime.now(), self.history_key)
            self.message_entry.delete(0, 'end')
            self.render_conversation()
            self.refresh_conversation_list()
        except (ConnectionError, OSError, ValueError, TimeoutError) as error:
            messagebox.showerror('Send Failed', str(error))

    def receive_messages(self):
        while self.running and self.client_socket:
            try:
                message = receive_json(self.client_socket)
                message_type = message.get('type')
                if message_type == 'response':
                    self.handle_response(message)
                elif message_type == 'encrypted_message':
                    self.handle_encrypted_message(message)
            except ConnectionError:
                if self.running:
                    self.root.after(0, self.handle_connection_closed)
                break
            except (ValueError, OSError):
                if self.running:
                    self.root.after(0, self.show_connection_error)
                break
            except Exception:
                if self.running:
                    self.root.after(0, self.show_connection_error)
                break

    def handle_response(self, response):
        request_id = response.get('request_id')
        if not request_id:
            return
        with self.pending_requests_lock:
            pending = self.pending_requests.get(request_id)
            if not pending:
                return
            pending['response'] = response
            pending['event'].set()

    def handle_encrypted_message(self, message):
        try:
            decrypted_message = decrypt_chat_message(message['encrypted_key'], message['nonce'], message['ciphertext'], self.private_key)
            sender = message.get('sender', 'Unknown')
            timestamp = datetime.now().strftime('%H:%M')
            self.conversations.setdefault(sender, []).append({'sender': sender, 'message': decrypted_message, 'time': timestamp, 'sent': False})
            save_message(self.username, sender, sender, decrypted_message, False, datetime.now(), self.history_key)
            if sender != self.active_recipient:
                self.unread_counts[sender] = self.unread_counts.get(sender, 0) + 1
            self.root.after(0, self.handle_received_message_ui, sender)
        except Exception:
            self.root.after(0, self.show_decryption_error)

    def handle_received_message_ui(self, sender):
        self.refresh_conversation_list()
        if sender == self.active_recipient:
            self.render_conversation()

    def show_empty_chat(self):
        self.chat_title.config(text='Welcome to Encrypted Chat')
        self.chat_status.config(text='Select a conversation')
        self.security_status.config(text='🔐 Secure messaging')
        for widget in self.message_container.winfo_children():
            widget.destroy()
        frame = tk.Frame(self.message_container, bg=self.colors['chat'])
        frame.pack(fill='both', expand=True, pady=150)
        tk.Label(frame, text='🔐', font=('Arial', 42), bg=self.colors['chat'], fg=self.colors['accent']).pack()
        tk.Label(frame, text='Your messages are encrypted', font=('Arial', 18, 'bold'), bg=self.colors['chat'], fg=self.colors['text']).pack(pady=(15, 5))
        tk.Label(frame, text='Start a new conversation to begin secure messaging.', font=('Arial', 10), bg=self.colors['chat'], fg=self.colors['muted']).pack()

    def show_connection_error(self):
        if hasattr(self, 'chat_status'):
            self.chat_status.config(text='Connection error')

    def show_decryption_error(self):
        messagebox.showerror('Message Error', 'The incoming encrypted message could not be decrypted.')

    def handle_connection_closed(self):
        self.running = False
        if hasattr(self, 'chat_status'):
            self.chat_status.config(text='● Server disconnected')
        if hasattr(self, 'security_status'):
            self.security_status.config(text='⚠ Disconnected')

    def show_profile(self):
        dialog = tk.Toplevel(self.root)
        dialog.title('Profile')
        dialog.geometry('400x360')
        dialog.resizable(False, False)
        dialog.configure(bg=self.colors['bg'])
        tk.Label(dialog, text='👤', font=('Arial', 38), bg=self.colors['bg'], fg=self.colors['accent']).pack(pady=(30, 5))
        tk.Label(dialog, text=self.username, font=('Arial', 20, 'bold'), bg=self.colors['bg'], fg=self.colors['text']).pack()
        tk.Label(dialog, text='Authenticated user', font=('Arial', 10), bg=self.colors['bg'], fg=self.colors['muted']).pack(pady=(3, 25))
        security_frame = tk.Frame(dialog, bg=self.colors['received'], padx=20, pady=15)
        security_frame.pack(fill='x', padx=35)
        tk.Label(security_frame, text='Security', font=('Arial', 10, 'bold'), bg=self.colors['received'], fg=self.colors['text']).pack(anchor='w')
        tk.Label(security_frame, text='✓ RSA-3072 key pair', font=('Arial', 9), bg=self.colors['received'], fg=self.colors['text']).pack(anchor='w', pady=(8, 2))
        tk.Label(security_frame, text='✓ AES-256-GCM encryption', font=('Arial', 9), bg=self.colors['received'], fg=self.colors['text']).pack(anchor='w', pady=2)
        tk.Label(security_frame, text='✓ RSA-OAEP key protection', font=('Arial', 9), bg=self.colors['received'], fg=self.colors['text']).pack(anchor='w', pady=2)

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        active_recipient = self.active_recipient
        conversations = self.conversations
        unread_counts = self.unread_counts
        public_keys = self.recipient_public_keys
        self.update_colors()
        self.build_chat_screen()
        self.conversations = conversations
        self.unread_counts = unread_counts
        self.recipient_public_keys = public_keys
        self.active_recipient = active_recipient
        if active_recipient:
            self.select_conversation(active_recipient)
        self.theme_button.config(text='☀ Light Mode' if self.dark_mode else '🌙 Dark Mode')

    def fail_pending_requests(self, message):
        with self.pending_requests_lock:
            for pending in self.pending_requests.values():
                pending['response'] = {'type': 'response', 'status': 'error', 'message': message}
                pending['event'].set()

    def logout(self):
        self.running = False
        self.receiver_started = False
        self.fail_pending_requests('Connection closed.')
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.client_socket.close()
            except OSError:
                pass
        self.client_socket = None
        self.username = None
        self.private_key = None
        self.history_key = None
        self.active_recipient = None
        self.recipient_public_keys = {}
        self.conversations = {}
        self.unread_counts = {}
        self.build_login_screen()

    def close_application(self):
        self.running = False
        self.fail_pending_requests('Application closed.')
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.client_socket.close()
            except OSError:
                pass
        self.history_key = None
        self.private_key = None
        self.root.destroy()

    def register(self):
        username = self.register_username_entry.get().strip()
        password = self.register_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        if not username:
            messagebox.showwarning('Registration', 'Please enter a username.')
            return
        if not validate_password(password):
            messagebox.showwarning('Registration', 'Password must be at least 8 characters long.')
            return
        if password != confirm_password:
            messagebox.showwarning('Registration', 'Passwords do not match.')
            return
        client_socket = None
        try:
            client_socket = self.connect_to_server()
            request = create_request('register', username=username, password=password)
            send_json(client_socket, request)
            response = receive_json(client_socket)
            if response.get('status') != 'success':
                messagebox.showerror('Registration Failed', response.get('message', 'Registration failed.'))
                return
            messagebox.showinfo('Registration Successful', 'Account created successfully.\n\nAn RSA key pair will be generated when you log in.')
            self.build_login_screen()
        except (ConnectionError, OSError, ValueError) as error:
            messagebox.showerror('Connection Error', f'Could not connect to the server.\n\n{error}')
        finally:
            if client_socket:
                client_socket.close()

def main():
    root = tk.Tk()
    EncryptedChatApp(root)
    root.mainloop()
if __name__ == '__main__':
    main()
