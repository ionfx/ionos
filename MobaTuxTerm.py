import sys
import os
import stat
import paramiko
import io
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QSplitter, QTextEdit, QLineEdit,
    QDialog, QFormLayout, QPushButton, QDialogButtonBox,
    QMessageBox, QStyle, QMenu, QFileDialog, QProgressDialog,
    QListWidget, QListWidgetItem, QInputDialog
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QFont

class ConnectionDialog(QDialog):
    """
    A dialog box to get SSH connection details from the user.
    Now includes a session name.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Connection Details")
        self.setModal(True)

        self.layout = QFormLayout(self)

        self.name_input = QLineEdit("My Server")
        self.host_input = QLineEdit("127.0.0.1")
        self.port_input = QLineEdit("22")
        self.user_input = QLineEdit("username")
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.layout.addRow("Session Name:", self.name_input)
        self.layout.addRow("Host:", self.host_input)
        self.layout.addRow("Port:", self.port_input)
        self.layout.addRow("Username:", self.user_input)
        self.layout.addRow("Password:", self.pass_input)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)

    def get_details(self):
        """Returns the connection details as a dictionary."""
        return {
            "name": self.name_input.text(),
            "host": self.host_input.text(),
            "port": int(self.port_input.text()),
            "user": self.user_input.text(),
            "password": self.pass_input.text()
        }

class RemoteTextEditorDialog(QDialog):
    """
    A dialog to edit a remote text file.
    """
    def __init__(self, remote_path, file_content, sftp_client, parent=None):
        super().__init__(parent)
        self.remote_path = remote_path
        self.sftp_client = sftp_client

        self.setWindowTitle(f"Editing: {remote_path}")
        self.setMinimumSize(800, 600)

        layout = QVBoxLayout(self)

        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Monospace", 10))
        self.text_edit.setText(file_content)
        layout.addWidget(self.text_edit)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self.save_file)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def save_file(self):
        """Saves the content back to the remote file via SFTP."""
        try:
            content = self.text_edit.toPlainText()
            content_bytes = content.encode('utf-8')

            # Use sftp_client.open to write
            with self.sftp_client.open(self.remote_path, 'w') as f:
                f.write(content_bytes)

            QMessageBox.information(self, "Save Successful", f"Successfully saved {self.remote_path}")
            self.accept() # Close the dialog

        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Could not save file:\n{e}")

class SessionManagerDialog(QDialog):
    """
    Manages loading, creating, and deleting sessions.
    Also handles the master password.
    """
    SESSIONS_FILE = "mobatuxterm_sessions.json"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("MobaTuxTerm Session Manager")
        self.setMinimumWidth(400)

        self.master_key = None
        self.salt = None
        self.sessions = []
        self.selected_session_details = None

        self.layout = QVBoxLayout(self)

        # Master Password
        self.pass_layout = QFormLayout()
        self.master_pass_input = QLineEdit()
        self.master_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_layout.addRow("Master Password:", self.master_pass_input)
        self.layout.addLayout(self.pass_layout)

        self.unlock_button = QPushButton("Unlock / Initialize")
        self.unlock_button.clicked.connect(self.unlock_sessions)
        self.layout.addWidget(self.unlock_button)

        # Session List (initially hidden)
        self.session_list_widget = QListWidget()
        self.session_list_widget.itemDoubleClicked.connect(self.connect_session)
        self.layout.addWidget(self.session_list_widget)

        # Buttons (initially hidden)
        self.button_layout = QHBoxLayout()
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_session)
        self.new_button = QPushButton("New...")
        self.new_button.clicked.connect(self.new_session)
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_session)

        self.button_layout.addWidget(self.connect_button)
        self.button_layout.addWidget(self.new_button)
        self.button_layout.addWidget(self.delete_button)
        self.layout.addLayout(self.button_layout)

        # Hide session UI until unlocked
        self.session_list_widget.hide()
        self.connect_button.hide()
        self.new_button.hide()
        self.delete_button.hide()

    def get_key_from_password(self, password, salt):
        """Derives a 32-byte key from password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def unlock_sessions(self):
        """Attempts to load and decrypt sessions with the given master password."""
        password = self.master_pass_input.text()
        if not password:
            QMessageBox.warning(self, "Password", "Please enter a master password.")
            return

        try:
            if os.path.exists(self.SESSIONS_FILE):
                # File exists, try to decrypt
                with open(self.SESSIONS_FILE, 'r') as f:
                    data = json.load(f)
                self.salt = base64.urlsafe_b64decode(data['salt'])
                self.master_key = self.get_key_from_password(password, self.salt)
                fernet = Fernet(base64.urlsafe_b64encode(self.master_key))

                self.sessions = []
                for s in data['sessions']:
                    s_decrypted = s.copy()
                    s_decrypted['password'] = fernet.decrypt(s['encrypted_password'].encode()).decode()
                    self.sessions.append(s_decrypted)

            else:
                # First time run: create new salt and use this password
                self.salt = os.urandom(16)
                self.master_key = self.get_key_from_password(password, self.salt)
                self.sessions = []
                self.save_sessions() # Save the empty file with salt
                QMessageBox.information(self, "Welcome", "Master password set. You can now create new sessions.")

            # Success! Show session UI
            self.master_pass_input.setDisabled(True)
            self.unlock_button.setDisabled(True)

            self.session_list_widget.show()
            self.connect_button.show()
            self.new_button.show()
            self.delete_button.show()

            self.populate_session_list()

        except Exception as e:
            self.master_key = None # Reset key on failure
            QMessageBox.critical(self, "Unlock Failed", f"Incorrect password or corrupted session file.\n{e}")

    def populate_session_list(self):
        self.session_list_widget.clear()
        for session in self.sessions:
            item = QListWidgetItem(f"{session['name']} ({session['user']}@{session['host']})")
            item.setData(Qt.ItemDataRole.UserRole, session)
            self.session_list_widget.addItem(item)

    def save_sessions(self):
        """Encrypts and saves all current sessions to file."""
        if not self.master_key or not self.salt:
            QMessageBox.critical(self, "Error", "Cannot save sessions without a master key.")
            return

        fernet = Fernet(base64.urlsafe_b64encode(self.master_key))
        encrypted_sessions = []
        for s in self.sessions:
            encrypted_s = s.copy()
            encrypted_s['encrypted_password'] = fernet.encrypt(s['password'].encode()).decode()
            del encrypted_s['password'] # Don't save plaintext password
            encrypted_sessions.append(encrypted_s)

        data = {
            'salt': base64.urlsafe_b64encode(self.salt).decode(),
            'sessions': encrypted_sessions
        }

        try:
            with open(self.SESSIONS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Could not write session file:\n{e}")

    def connect_session(self):
        """Sets the selected session and accepts the dialog."""
        selected_item = self.session_list_widget.currentItem()
        if not selected_item:
            return

        self.selected_session_details = selected_item.data(Qt.ItemDataRole.UserRole)
        self.accept()

    def new_session(self):
        """Shows the ConnectionDialog to create a new session."""
        conn_dialog = ConnectionDialog(self)
        if conn_dialog.exec() == QDialog.DialogCode.Accepted:
            new_session_details = conn_dialog.get_details()
            # Check for duplicate names
            if any(s['name'] == new_session_details['name'] for s in self.sessions):
                QMessageBox.warning(self, "Duplicate Name", "A session with this name already exists.")
                return

            self.sessions.append(new_session_details)
            self.save_sessions()
            self.populate_session_list()

    def delete_session(self):
        """Deletes the selected session."""
        selected_item = self.session_list_widget.currentItem()
        if not selected_item:
            return

        session_data = selected_item.data(Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete session '{session_data['name']}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.sessions = [s for s in self.sessions if s['name'] != session_data['name']]
            self.save_sessions()
            self.populate_session_list()

    def get_selected_session(self):
        return self.selected_session_details

class MainWindow(QMainWindow):
    """
    The main application window.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MobaTuxTerm - for IonOS")
        self.setGeometry(100, 100, 1200, 800)

        self.ssh_client = None
        self.sftp_client = None
        self.current_remote_path = ""
        self.local_path = os.path.expanduser("~") # Default local path

        # --- Icons ---
        self.folder_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.file_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)

        # Build the UI first
        self.init_ui()

        # Show session manager on startup
        if not self.show_session_manager():
            sys.exit(0) # Exit if session manager is cancelled

        # post_connection_setup() is now called *after* connect_ssh succeeds
        # inside show_session_manager()

    def show_session_manager(self):
        """
        Shows the session manager. If a session is chosen,
        it attempts to connect.
        Returns True on successful connection, False on cancel/failure.
        """
        dialog = SessionManagerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            session = dialog.get_selected_session()
            if session:
                if self.connect_ssh(session['host'], session['port'], session['user'], session['password']):
                    self.post_connection_setup() # Call setup *after* connection
                    return True
        return False

    def connect_ssh(self, host, port, user, password):
        """
        Establishes the SSH and SFTP connection.
        """
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=5
            )

            self.sftp_client = self.ssh_client.open_sftp()
            self.current_remote_path = self.sftp_client.getcwd()
            if self.current_remote_path is None:
                self.current_remote_path = self.sftp_client.normalize('.')

            self.setWindowTitle(f"MobaTuxTerm - {user}@{host}")
            return True

        except Exception as e:
            QMessageBox.critical(
                self, "Connection Error", f"Could not connect to {host}:{port}\n{e}"
            )
            return False

    def init_ui(self):
        """
        Initializes the main User Interface components.
        This can safely run before a connection is established.
        """
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)

        # --- Main Splitter ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # --- Left Side: SFTP Browser ---
        self.sftp_browser = QTreeWidget()
        self.sftp_browser.setHeaderLabels(["Name", "Size", "Type", "Permissions"])
        self.sftp_browser.setColumnWidth(0, 300)
        self.sftp_browser.itemDoubleClicked.connect(self.sftp_item_double_clicked)
        self.sftp_browser.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.sftp_browser.customContextMenuRequested.connect(self.sftp_context_menu)
        splitter.addWidget(self.sftp_browser)

        # --- Right Side: Terminal ---
        terminal_widget = QWidget()
        terminal_layout = QVBoxLayout(terminal_widget)
        terminal_layout.setContentsMargins(0, 0, 0, 0)

        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Monospace", 10))
        self.terminal_output.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")

        self.terminal_input = QLineEdit()
        self.terminal_input.setFont(QFont("Monospace", 10))
        self.terminal_input.setStyleSheet("background-color: #252526; color: #d4d4d4; border: 1px solid #333;")
        self.terminal_input.returnPressed.connect(self.execute_command)

        terminal_layout.addWidget(self.terminal_output)
        terminal_layout.addWidget(self.terminal_input)
        splitter.addWidget(terminal_widget)

        splitter.setSizes([400, 800]) # Initial size ratio

    def post_connection_setup(self):
        """
        Populates the UI after a successful connection.
        """
        if self.sftp_client:
            self.populate_sftp_browser(self.current_remote_path)
            self.update_terminal_prompt()
            self.terminal_input.setFocus()

            # Run a welcome command
            self.execute_command(command_str="echo 'Welcome to MobaTuxTerm!' && uname -a", internal=True)

    def populate_sftp_browser(self, path):
        """
        Fetches directory listing from SFTP and populates the tree widget.
        """
        try:
            self.sftp_client.chdir(path)
            self.current_remote_path = self.sftp_client.getcwd()
            self.sftp_browser.clear()

            # Add ".." item to go up
            up_item = QTreeWidgetItem(["..", "", "Parent Directory", ""])
            up_item.setIcon(0, self.folder_icon)
            up_item.setData(0, Qt.ItemDataRole.UserRole, {"is_dir": True, "filename": ".."})
            self.sftp_browser.addTopLevelItem(up_item)

            # Get directory listing
            items = self.sftp_client.listdir_attr('.')
            # Sort items: directories first, then by name
            items.sort(key=lambda x: (not stat.S_ISDIR(x.st_mode), x.filename.lower()))

            for item in items:
                filename = item.filename
                if filename in ('.', '..'):
                    continue

                is_dir = stat.S_ISDIR(item.st_mode)
                file_type = "Directory" if is_dir else "File"
                size = str(item.st_size) if not is_dir else ""
                permissions = stat.filemode(item.st_mode)

                tree_item = QTreeWidgetItem([filename, size, file_type, permissions])
                tree_item.setIcon(0, self.folder_icon if is_dir else self.file_icon)

                # Store metadata in the item
                item_data = {
                    "is_dir": is_dir,
                    "filename": filename,
                    "full_path": self.sftp_client.normalize(os.path.join(self.current_remote_path, filename))
                }
                tree_item.setData(0, Qt.ItemDataRole.UserRole, item_data)

                self.sftp_browser.addTopLevelItem(tree_item)

            self.update_terminal_prompt()

        except Exception as e:
            QMessageBox.warning(self, "SFTP Error", f"Could not list directory {path}:\n{e}")

    def sftp_item_double_clicked(self, item, column):
        """
        Handles navigation or opening the file editor.
        """
        item_data = item.data(0, Qt.ItemDataRole.UserRole)
        if not item_data:
            return

        if item_data["is_dir"]:
            # Directory navigation
            filename = item_data["filename"]
            new_path = self.sftp_client.normalize(os.path.join(self.current_remote_path, filename))
            self.populate_sftp_browser(new_path)
        else:
            # File: Open text editor
            self.open_remote_file_editor(item_data)

    def open_remote_file_editor(self, item_data):
        """
        Downloads a remote file and opens it in the text editor dialog.
        """
        remote_path = item_data["full_path"]

        # Add a "loading" cursor
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

        try:
            with self.sftp_client.open(remote_path, 'r') as f:
                content_bytes = f.read()

            # Try to decode as UTF-8, fallback to latin-1
            try:
                content_str = content_bytes.decode('utf-8')
            except UnicodeDecodeError:
                content_str = content_bytes.decode('latin-1')

            QApplication.restoreOverrideCursor() # Restore cursor

            # Open the editor dialog
            editor = RemoteTextEditorDialog(remote_path, content_str, self.sftp_client, self)
            if editor.exec() == QDialog.DialogCode.Accepted:
                # File was saved, refresh the SFTP browser to show new size/date
                self.populate_sftp_browser(self.current_remote_path)

        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Error Opening File", f"Could not open {remote_path}:\n{e}")

    def update_terminal_prompt(self):
        """
        Updates the terminal prompt display.
        (This is just visual, the real path is tracked internally)
        """
        prompt = f"[{self.current_remote_path}]$ "
        self.terminal_input.setPlaceholderText(prompt)
        self.terminal_output.moveCursor(self.terminal_output.textCursor().MoveOperation.End)


    def execute_command(self, command_str=None, internal=False):
        """
        Executes a command on the remote server via SSH.
        """
        if command_str is None:
            command = self.terminal_input.text().strip()
        else:
            command = command_str

        if not command:
            return

        if not internal:
            self.terminal_output.append(f"[{self.current_remote_path}]$ {command}")
            self.terminal_input.clear()

        # Check for 'cd' command to sync SFTP browser
        if command.startswith("cd "):
            try:
                new_path = command.split(" ", 1)[1].strip()

                # We must run `cd` and `pwd` in the same exec_command
                # to get the *resolved* new path.
                full_cd_command = f"cd {self.current_remote_path} && cd {new_path} && pwd"
                stdin, stdout, stderr = self.ssh_client.exec_command(full_cd_command)

                new_cwd = stdout.read().decode().strip()
                err = stderr.read().decode().strip()

                if new_cwd and not err:
                    # Success! Update SFTP browser
                    self.populate_sftp_browser(new_cwd)
                elif err:
                    self.terminal_output.append(f"STDERR: {err}")
            except Exception as e:
                self.terminal_output.append(f"Error processing 'cd': {e}")
        else:
            # Execute a normal command
            # Prepend 'cd' to ensure it runs in the correct directory
            full_command = f"cd {self.current_remote_path} && {command}"

            try:
                stdin, stdout, stderr = self.ssh_client.exec_command(full_command, get_pty=True)

                output = stdout.read().decode().strip()
                err = stderr.read().decode().strip()

                if output:
                    self.terminal_output.append(output)
                if err:
                    self.terminal_output.append(f"STDERR: {err}")

            except Exception as e:
                self.terminal_output.append(f"Command execution error: {e}")

        self.update_terminal_prompt()

    def sftp_context_menu(self, position):
        """
        Creates and shows the right-click context menu for the SFTP browser.
        """
        menu = QMenu()
        selected_item = self.sftp_browser.itemAt(position)

        upload_file_action = menu.addAction("Upload File(s)...")
        upload_dir_action = menu.addAction("Upload Directory...")
        menu.addSeparator()

        if selected_item:
            item_data = selected_item.data(0, Qt.ItemDataRole.UserRole)
            if item_data and not item_data['is_dir']:
                edit_action = menu.addAction(QIcon.fromTheme("document-edit"), "Edit File")
                menu.addSeparator()
            else:
                edit_action = None

            download_action = menu.addAction(QIcon.fromTheme("go-down"), "Download")
            delete_action = menu.addAction(QIcon.fromTheme("edit-delete"), "Delete")
            menu.addSeparator()
        else:
            edit_action = None
            download_action = None
            delete_action = None

        create_dir_action = menu.addAction(QIcon.fromTheme("folder-new"), "Create Directory...")

        action = menu.exec(self.sftp_browser.mapToGlobal(position))

        if action == upload_file_action:
            self.upload_files()
        elif action == upload_dir_action:
            self.upload_directory()
        elif selected_item and action == edit_action:
            self.open_remote_file_editor(selected_item.data(0, Qt.ItemDataRole.UserRole))
        elif selected_item and action == download_action:
            self.download_item(selected_item)
        elif selected_item and action == delete_action:
            self.delete_item(selected_item)
        elif action == create_dir_action:
            self.create_directory()

    def download_item(self, item):
        item_data = item.data(0, Qt.ItemDataRole.UserRole)
        if item_data['filename'] == '..': return

        remote_path = item_data["full_path"]
        is_dir = item_data["is_dir"]

        local_path = QFileDialog.getExistingDirectory(self, "Select Download Location", self.local_path)
        if not local_path:
            return

        self.local_path = local_path # Save for next time
        local_dest = os.path.join(local_path, item_data["filename"])

        try:
            if is_dir:
                self.download_directory_recursive(remote_path, local_dest)
            else:
                self.download_file(remote_path, local_dest)
            QMessageBox.information(self, "Download Complete", f"Successfully downloaded '{remote_path}' to '{local_dest}'")
        except Exception as e:
            QMessageBox.critical(self, "Download Error", f"Failed to download:\n{e}")

    def download_file(self, remote_path, local_path):
        """Helper to download a single file with progress."""
        progress = QProgressDialog(f"Downloading {os.path.basename(remote_path)}...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)

        def progress_callback(sent, total):
            if total > 0:
                progress.setValue(int(sent / total * 100))
            else:
                progress.setValue(0) # Handle zero-byte files
            if progress.wasCanceled():
                raise InterruptedError("Download cancelled by user.")

        try:
            # Handle potential zero-byte file case for callback
            file_size = self.sftp_client.stat(remote_path).st_size
            if file_size == 0:
                self.sftp_client.get(remote_path, local_path)
                progress.setValue(100)
            else:
                self.sftp_client.get(remote_path, local_path, callback=progress_callback)
        except InterruptedError:
            if os.path.exists(local_path):
                os.remove(local_path)
            self.terminal_output.append(f"Download of {remote_path} cancelled.")

    def download_directory_recursive(self, remote_dir, local_dir):
        """Recursively downloads a directory."""
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)

        for item in self.sftp_client.listdir_attr(remote_dir):
            remote_item_path = self.sftp_client.normalize(os.path.join(remote_dir, item.filename))
            local_item_path = os.path.join(local_dir, item.filename)

            if stat.S_ISDIR(item.st_mode):
                self.download_directory_recursive(remote_item_path, local_item_path)
            else:
                self.download_file(remote_item_path, local_item_path)

    def upload_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select File(s) to Upload", self.local_path)
        if not files:
            return

        self.local_path = os.path.dirname(files[0]) # Save for next time

        for local_file in files:
            try:
                filename = os.path.basename(local_file)
                remote_path = self.sftp_client.normalize(os.path.join(self.current_remote_path, filename))
                self.upload_file_with_progress(local_file, remote_path)
            except Exception as e:
                QMessageBox.critical(self, "Upload Error", f"Failed to upload {local_file}:\n{e}")
        self.populate_sftp_browser(self.current_remote_path) # Refresh

    def upload_file_with_progress(self, local_path, remote_path):
        """Helper to upload a single file with progress."""
        progress = QProgressDialog(f"Uploading {os.path.basename(local_path)}...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)

        def progress_callback(sent, total):
            if total > 0:
                progress.setValue(int(sent / total * 100))
            else:
                progress.setValue(0) # Handle zero-byte files
            if progress.wasCanceled():
                raise InterruptedError("Upload cancelled by user.")

        try:
            file_size = os.path.getsize(local_path)
            if file_size == 0:
                self.sftp_client.put(local_path, remote_path)
                progress.setValue(100)
            else:
                self.sftp_client.put(local_path, remote_path, callback=progress_callback)
        except InterruptedError:
            self.terminal_output.append(f"Upload of {local_path} cancelled.")
            # We should probably delete the partial remote file
            try:
                self.sftp_client.remove(remote_path)
                self.terminal_output.append(f"Removed partial remote file {remote_path}")
            except Exception as e:
                self.terminal_output.append(f"Could not remove partial file {remote_path}: {e}")

    def upload_directory(self):
        local_dir = QFileDialog.getExistingDirectory(self, "Select Directory to Upload", self.local_path)
        if not local_dir:
            return

        self.local_path = local_dir
        dir_name = os.path.basename(local_dir)
        remote_dir = self.sftp_client.normalize(os.path.join(self.current_remote_path, dir_name))

        try:
            self.sftp_client.mkdir(remote_dir)
        except Exception as e:
            # Handle error more gracefully, check if it's "File exists"
            try:
                # If it's not a directory, we have a problem
                if not stat.S_ISDIR(self.sftp_client.stat(remote_dir).st_mode):
                     QMessageBox.critical(self, "Upload Error", f"A file (not directory) already exists at {remote_dir}:\n{e}")
                     return
            except Exception:
                 # If stat fails, the error was something else
                QMessageBox.critical(self, "Upload Error", f"Failed to create directory {remote_dir}:\n{e}")
                return

        try:
            self.upload_directory_recursive(local_dir, remote_dir)
            QMessageBox.information(self, "Upload Complete", f"Successfully uploaded '{local_dir}' to '{remote_dir}'")
        except Exception as e:
            QMessageBox.critical(self, "Upload Error", f"Failed during recursive upload:\n{e}")

        self.populate_sftp_browser(self.current_remote_path) # Refresh

    def upload_directory_recursive(self, local_dir, remote_dir):
        """Recursively uploads a directory."""
        for item_name in os.listdir(local_dir):
            local_item_path = os.path.join(local_dir, item_name)
            remote_item_path = self.sftp_client.normalize(os.path.join(remote_dir, item_name))

            if os.path.isdir(local_item_path):
                try:
                    self.sftp_client.mkdir(remote_item_path)
                except Exception as e:
                    # If dir exists, ignore error and continue
                    try:
                        if not stat.S_ISDIR(self.sftp_client.stat(remote_item_path).st_mode):
                            raise e # It's a file, raise error
                    except Exception:
                        raise e # Some other error
                self.upload_directory_recursive(local_item_path, remote_item_path)
            else:
                self.upload_file_with_progress(local_item_path, remote_item_path)

    def delete_item(self, item):
        item_data = item.data(0, Qt.ItemDataRole.UserRole)
        filename = item_data["filename"]
        if filename == "..":
            return

        remote_path = item_data["full_path"]
        is_dir = item_data["is_dir"]

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to permanently delete '{filename}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                if is_dir:
                    self.delete_directory_recursive(remote_path)
                else:
                    self.sftp_client.remove(remote_path)
                self.terminal_output.append(f"Deleted {remote_path}")
            except Exception as e:
                QMessageBox.critical(self, "Delete Error", f"Failed to delete {remote_path}:\n{e}")

            self.populate_sftp_browser(self.current_remote_path) # Refresh

    def delete_directory_recursive(self, remote_dir):
        """Recursivley deletes a remote directory."""
        # This is complex as SFTP has no recursive delete.
        # We must walk the tree and delete files, then dirs.
        for item in self.sftp_client.listdir_attr(remote_dir):
            remote_item_path = self.sftp_client.normalize(os.path.join(remote_dir, item.filename))
            if stat.S_ISDIR(item.st_mode):
                self.delete_directory_recursive(remote_item_path)
            else:
                self.sftp_client.remove(remote_item_path)
        # Finally, remove the now-empty directory
        self.sftp_client.rmdir(remote_dir)

    def create_directory(self):
        dir_name, ok = QInputDialog.getText(self, "Create Directory", "Enter new directory name:")
        if ok and dir_name:
            try:
                remote_path = self.sftp_client.normalize(os.path.join(self.current_remote_path, dir_name))
                self.sftp_client.mkdir(remote_path)
                self.terminal_output.append(f"Created directory {remote_path}")
                self.populate_sftp_browser(self.current_remote_path) # Refresh
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create directory:\n{e}")

    def closeEvent(self, event):
        """
        Handles the window close event to safely close connections.
        """
        if self.sftp_client:
            self.sftp_client.close()
        if self.ssh_client:
            self.ssh_client.close()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    if window.ssh_client: # Only show if connection was successful
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit(1) # Exit if no connection

