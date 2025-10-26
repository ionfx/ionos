import sys
import os
import requests
# import py7zr # No longer needed
import json
import shutil
import subprocess # <--- Import subprocess
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QLabel, QProgressBar, QMessageBox, QFileDialog, QTextEdit, QInputDialog
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer

# --- Configuration ---
APP_NAME = "OptiScaler Installer"
GITHUB_REPO = "optiscaler/OptiScaler"
CACHE_DIR = Path.home() / ".local" / "share" / "optiscaler_installer"
VERSION_FILE = CACHE_DIR / "current_version.txt"
RELEASE_DIR = CACHE_DIR / "latest_release"

# --- Function to check for 7z command ---
def check_7z_command():
    """Checks if the 7z command is available."""
    try:
        if shutil.which("7z"): return True
        else:
            if shutil.which("7zz"): return True
            if shutil.which("p7zip"): return True
        return False
    except Exception: return False

# Function to get the correct 7z command name
def get_7z_command_name():
    if shutil.which("7z"): return "7z"
    if shutil.which("7zz"): return "7zz"
    if shutil.which("p7zip"): return "p7zip" # Less likely for extraction
    return None

# --- GitHub API Thread ---
class GithubFetchThread(QThread):
    result_ready = pyqtSignal(dict, str)
    def run(self):
        api_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        try:
            print(f"Fetching release info from: {api_url}")
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            release_data = response.json()
            self.result_ready.emit(release_data, "")
        except requests.exceptions.Timeout:
             self.result_ready.emit({}, "Network Error: Connection timed out.")
        except requests.exceptions.ConnectionError:
            self.result_ready.emit({}, "Network Error: Could not connect to GitHub.")
        except requests.exceptions.RequestException as e:
            self.result_ready.emit({}, f"Network Error: {e}")
        except json.JSONDecodeError:
            self.result_ready.emit({}, "Error: Invalid response from GitHub API.")
        except Exception as e:
            self.result_ready.emit({}, f"An unexpected error occurred: {e}")

# --- Download Thread ---
class DownloadThread(QThread):
    progress_updated = pyqtSignal(int)
    download_finished = pyqtSignal(bool, str)
    def __init__(self, url, save_path):
        super().__init__()
        self.url = url
        self.save_path = save_path
        self._is_cancelled = False
    def run(self):
        try:
            response = requests.get(self.url, stream=True, timeout=15)
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            bytes_downloaded = 0
            chunk_size = 8192
            Path(self.save_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if self._is_cancelled:
                        self.download_finished.emit(False, "Download cancelled.")
                        if os.path.exists(self.save_path): os.remove(self.save_path)
                        return
                    if chunk:
                        f.write(chunk)
                        bytes_downloaded += len(chunk)
                        if total_size > 0:
                            progress = int((bytes_downloaded / total_size) * 100)
                            self.progress_updated.emit(progress)
            if not self._is_cancelled:
                self.progress_updated.emit(100)
                self.download_finished.emit(True, str(self.save_path))
        except requests.exceptions.RequestException as e:
             self.download_finished.emit(False, f"Download Error: {e}")
             if os.path.exists(self.save_path): os.remove(self.save_path)
        except Exception as e:
            self.download_finished.emit(False, f"An unexpected error during download: {e}")
            if os.path.exists(self.save_path): os.remove(self.save_path)
    def cancel(self): self._is_cancelled = True


# --- Main Application Window ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setGeometry(200, 200, 500, 450)

        self.current_local_version = self.get_local_version()
        self.latest_github_version = "N/A"
        self.latest_download_url = None
        self.download_thread = None
        self.github_fetch_thread = None
        self.seven_zip_command = get_7z_command_name()

        # --- UI Elements ---
        self.central_widget = QWidget()
        self.layout = QVBoxLayout(self.central_widget)

        self.status_label = QLabel(f"Local OptiScaler Version: {self.current_local_version}")
        self.github_status_label = QLabel("Latest GitHub Version: Checking...")
        self.update_button = QPushButton("Check for / Install Updates")
        self.enable_button = QPushButton("Enable OptiScaler for Game...")
        self.disable_button = QPushButton("Disable OptiScaler for Game (TODO)")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.debug_output = QTextEdit()
        self.debug_output.setReadOnly(True)
        self.debug_output.setVisible(False)
        self.debug_output.setMaximumHeight(100)

        self.layout.addWidget(self.status_label)
        self.layout.addWidget(self.github_status_label)
        self.layout.addWidget(self.update_button)
        self.layout.addWidget(self.enable_button)
        self.layout.addWidget(self.disable_button)
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(QLabel("Debug Log:"))
        self.layout.addWidget(self.debug_output)
        self.layout.addStretch()

        self.enable_button.setEnabled(RELEASE_DIR.exists())
        self.disable_button.setEnabled(False)

        self.setCentralWidget(self.central_widget)

        # --- Connect Signals ---
        self.update_button.clicked.connect(self.check_for_updates)
        self.enable_button.clicked.connect(self.enable_for_game)

        # --- Initial Check ---
        QTimer.singleShot(100, self.fetch_latest_release_info)

    def log_debug(self, message):
        print(message)
        self.debug_output.append(message)
        self.debug_output.setVisible(True)

    def get_local_version(self):
        try:
            if VERSION_FILE.exists(): return VERSION_FILE.read_text().strip()
            else: return "Not Installed"
        except Exception as e:
            self.log_debug(f"Error reading version file: {e}")
            return "Error Reading Version"

    def save_local_version(self, version_tag):
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            VERSION_FILE.write_text(version_tag)
            self.current_local_version = version_tag
            self.status_label.setText(f"Local OptiScaler Version: {self.current_local_version}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not save version file: {e}")

    def fetch_latest_release_info(self):
        # ... (fetch_latest_release_info remains the same) ...
        if self.github_fetch_thread and self.github_fetch_thread.isRunning(): return
        self.log_debug("Starting GitHub check...")
        self.github_status_label.setText("Latest GitHub Version: Checking...")
        self.update_button.setEnabled(False)
        self.github_fetch_thread = GithubFetchThread()
        self.github_fetch_thread.result_ready.connect(self.on_github_info_fetched)
        self.github_fetch_thread.start()

    def on_github_info_fetched(self, release_data, error_message):
        # ... (on_github_info_fetched remains the same, looking for .7z) ...
        self.log_debug("GitHub check finished.")
        self.update_button.setEnabled(True)
        if error_message:
            self.github_status_label.setText(f"Latest GitHub Version: Error")
            self.log_debug(f"GitHub Fetch Error: {error_message}")
            QMessageBox.warning(self, "GitHub Error", error_message)
            return
        try:
            self.latest_github_version = release_data.get("tag_name", "N/A")
            assets = release_data.get("assets", [])
            self.log_debug(f"Found {len(assets)} assets in release {self.latest_github_version}:")
            asset_names = []
            for asset in assets:
                 asset_name = asset.get("name", "Unknown Asset Name")
                 asset_names.append(asset_name)
                 self.log_debug(f"- {asset_name}")
            archive_asset = None
            for asset in assets:
                asset_name = asset.get("name", "")
                if asset_name.lower().endswith(".7z"):
                    archive_asset = asset
                    self.log_debug(f"Found .7z asset: {asset_name}")
                    break
            if archive_asset:
                self.latest_download_url = archive_asset.get("browser_download_url")
                self.github_status_label.setText(f"Latest GitHub Version: {self.latest_github_version}")
                if self.current_local_version == self.latest_github_version and RELEASE_DIR.exists():
                    self.update_button.setText("OptiScaler is Up-to-Date")
                    self.update_button.setEnabled(False)
                    self.enable_button.setEnabled(True)
                else:
                     self.update_button.setText(f"Install/Update to {self.latest_github_version}")
                     self.update_button.setEnabled(True)
                     self.enable_button.setEnabled(RELEASE_DIR.exists())
            else:
                self.github_status_label.setText("Latest GitHub Version: Error (No .7z found)")
                self.log_debug("ERROR: Could not find any asset ending in .7z")
                self.latest_download_url = None
                self.enable_button.setEnabled(RELEASE_DIR.exists())
        except Exception as e:
             self.github_status_label.setText("Latest GitHub Version: Error parsing data")
             self.log_debug(f"Error processing release data: {e}")
             QMessageBox.warning(self, "GitHub Error", f"Error processing release data: {e}")
             self.enable_button.setEnabled(RELEASE_DIR.exists())

    def check_for_updates(self):
        # ... (check_for_updates remains the same) ...
        if not self.latest_download_url: QMessageBox.warning(self, "Error", "Could not determine download URL..."); self.fetch_latest_release_info(); return
        if self.current_local_version == self.latest_github_version and RELEASE_DIR.exists(): QMessageBox.information(self, "Up-to-Date", "You already have the latest version."); return
        if not self.seven_zip_command: QMessageBox.critical(self, "Dependency Error", f"Could not find 7z command..."); return
        reply = QMessageBox.question(self, "Confirm Download", f"Download OptiScaler {self.latest_github_version}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes)
        if reply == QMessageBox.StandardButton.Yes: self.start_download()

    def start_download(self):
        # ... (start_download remains the same) ...
        if not self.latest_download_url or not self.latest_github_version: QMessageBox.critical(self, "Error", "Missing URL/version."); return
        if not self.seven_zip_command: QMessageBox.critical(self, "Dependency Error", "7z command not found."); return
        if self.download_thread and self.download_thread.isRunning():
             reply = QMessageBox.question(self, "Download in Progress", "Cancel current download?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
             if reply == QMessageBox.StandardButton.Yes: self.download_thread.cancel()
             else: return
        archive_filename = self.latest_download_url.split('/')[-1]
        save_path = CACHE_DIR / archive_filename
        self.progress_bar.setValue(0); self.progress_bar.setVisible(True)
        self.update_button.setEnabled(False); self.enable_button.setEnabled(False)
        self.status_label.setText(f"Downloading {self.latest_github_version}...")
        self.log_debug(f"Starting download from {self.latest_download_url} to {save_path}")
        self.download_thread = DownloadThread(self.latest_download_url, save_path)
        self.download_thread.progress_updated.connect(self.update_progress)
        self.download_thread.download_finished.connect(self.on_download_finished)
        self.download_thread.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def on_download_finished(self, success, message_or_filepath):
        # ... (on_download_finished remains the same) ...
        self.progress_bar.setVisible(False)
        self.update_button.setEnabled(True)
        if success:
            archive_filepath = Path(message_or_filepath)
            self.log_debug(f"Download successful: {archive_filepath}")
            self.status_label.setText("Download complete. Extracting...")
            QApplication.processEvents()
            if self.extract_optiscaler(archive_filepath):
                 self.save_local_version(self.latest_github_version)
                 QMessageBox.information(self, "Success", f"OptiScaler {self.latest_github_version} downloaded and extracted.")
                 self.enable_button.setEnabled(True)
                 self.update_button.setText("OptiScaler is Up-to-Date"); self.update_button.setEnabled(False)
            else:
                self.status_label.setText(f"Local OptiScaler Version: {self.current_local_version}")
                self.enable_button.setEnabled(RELEASE_DIR.exists())
            try: archive_filepath.unlink()
            except OSError as e: self.log_debug(f"Warning: Could not delete archive {archive_filepath}: {e}")
        else:
            self.log_debug(f"Download failed: {message_or_filepath}")
            QMessageBox.critical(self, "Download Failed", message_or_filepath)
            self.status_label.setText(f"Local OptiScaler Version: {self.current_local_version}")
            self.enable_button.setEnabled(RELEASE_DIR.exists())

    def extract_optiscaler(self, archive_filepath):
        # ... (extract_optiscaler remains the same, using 7z command) ...
        self.log_debug(f"Attempting to extract {archive_filepath} to {RELEASE_DIR} using '{self.seven_zip_command}'")
        if not self.seven_zip_command: QMessageBox.critical(self, "Extraction Error", "7z command not found."); return False
        try:
            if RELEASE_DIR.exists(): shutil.rmtree(RELEASE_DIR)
            RELEASE_DIR.mkdir(parents=True, exist_ok=True)
            command = [self.seven_zip_command, 'x', str(archive_filepath), f'-o{str(RELEASE_DIR)}', '-y']
            self.log_debug(f"Running command: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                if result.returncode == 1:
                     self.log_debug(f"7z extraction warnings (Code 1):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
                     if not list(RELEASE_DIR.iterdir()): raise RuntimeError("Extraction warning but output dir empty.")
                     QMessageBox.warning(self, "Extraction Warning", f"Warnings during extraction. Check log.")
                else:
                    self.log_debug(f"7z extraction failed (Code {result.returncode}):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
                    raise RuntimeError(f"7z failed. STDERR: {result.stderr[:200]}...")
            self.log_debug(f"Extraction successful.")
            return True
        except FileNotFoundError:
             self.log_debug(f"Extraction Error: Command '{self.seven_zip_command}' not found.")
             QMessageBox.critical(self, "Extraction Error", f"Command '{self.seven_zip_command}' not found."); return False
        except Exception as e:
            self.log_debug(f"Extraction Error: {e}")
            QMessageBox.critical(self, "Extraction Error", f"Failed extraction: {e}"); return False

    # --- UPDATED: enable_for_game method (Registry step removed) ---
    def enable_for_game(self):
        """Guides the user through enabling OptiScaler for a specific game."""
        self.log_debug("Starting 'Enable for Game' process...")

        # 1. Check if OptiScaler files are cached
        if not RELEASE_DIR.exists() or not any(RELEASE_DIR.iterdir()):
            QMessageBox.warning(self, "Files Not Found",
                                "OptiScaler files not found locally. Please use 'Check for / Install Updates' first.")
            self.log_debug("Enable aborted: Release directory not found or empty.")
            return

        # 2. Explain and get Game Directory
        QMessageBox.information(self, "Select Game Folder",
                                "Please select the folder containing the game's main executable file (e.g., the .exe file).\n\n"
                                "For Unreal Engine games, this is often inside a 'Binaries/Win64' subfolder.")
        game_dir_str = QFileDialog.getExistingDirectory(self, "Select Game Executable Folder", str(Path.home()))

        if not game_dir_str:
            self.log_debug("Enable aborted: User cancelled game directory selection.")
            return # User cancelled

        game_dir = Path(game_dir_str)
        self.log_debug(f"Game directory selected: {game_dir}")

        # 3. Copy Files (with overwrite checks for key files)
        self.log_debug(f"Copying files from {RELEASE_DIR} to {game_dir}")
        files_to_check_overwrite = ["OptiScaler.dll", "OptiScaler.ini",
                                    "nvngx.dll", "libxess.dll", "libxess_dx11.dll",
                                    "amd_fidelityfx_dx12.dll", "amd_fidelityfx_framegeneration_dx12.dll",
                                    "amd_fidelityfx_upscaler_dx12.dll", "amd_fidelityfx_vk.dll"]
        try:
            items_copied_count = 0
            for item in RELEASE_DIR.iterdir():
                # Skip setup scripts and readme during copy
                if item.name.lower() in ["_setup_linux.sh", "_setup_windows.bat", "!! extract all files to game folder !!"]:
                    continue

                dest_path = game_dir / item.name
                if item.is_dir():
                    # Backup directory before removing? Maybe too complex for now.
                    # Simple overwrite for directories.
                    # Use copytree with dirs_exist_ok=True instead of manual removal
                    shutil.copytree(item, dest_path, dirs_exist_ok=True)
                    self.log_debug(f"Copied/Updated directory: {item.name}")
                    items_copied_count += 1 # Count directory as one item
                elif item.is_file():
                    backup_made = False
                    if dest_path.exists() and item.name in files_to_check_overwrite:
                        reply = QMessageBox.question(self, "Confirm Overwrite",
                                                     f"'{item.name}' already exists in the game folder. Overwrite it?",
                                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Save,
                                                     QMessageBox.StandardButton.Yes)
                        if reply == QMessageBox.StandardButton.No:
                            self.log_debug(f"Skipped overwriting {item.name}")
                            continue
                        elif reply == QMessageBox.StandardButton.Save:
                            backup_path = dest_path.with_suffix(dest_path.suffix + ".bak")
                            try:
                                # Ensure we don't overwrite a previous backup
                                backup_attempts = 0
                                while backup_path.exists() and backup_attempts < 10:
                                     backup_attempts += 1
                                     backup_path = backup_path.with_suffix(f".bak{backup_attempts}")
                                if backup_path.exists(): raise OSError("Too many backup files exist.")

                                shutil.move(str(dest_path), str(backup_path))
                                self.log_debug(f"Backed up existing {item.name} to {backup_path.name}")
                                backup_made = True
                            except OSError as e:
                                QMessageBox.warning(self, "Backup Error", f"Could not back up {item.name}: {e}")
                                continue
                    # Copy the new file
                    try:
                        shutil.copy2(item, dest_path)
                        self.log_debug(f"Copied file: {item.name}" + (" (Overwritten)" if dest_path.exists() and not backup_made else ""))
                        items_copied_count += 1
                    except Exception as e:
                        if backup_made: # Rollback backup if copy failed
                             try: shutil.move(str(backup_path), str(dest_path))
                             except Exception as bk_e: self.log_debug(f"Rollback of backup failed: {bk_e}")
                        raise e # Re-raise original copy error

            # Check if source directory might have been empty
            if items_copied_count == 0 and not any(f for f in RELEASE_DIR.iterdir() if f.name.lower() not in ["_setup_linux.sh", "_setup_windows.bat", "!! extract all files to game folder !!"]):
                 raise RuntimeError("Source directory was empty or contained only setup files.")
            elif items_copied_count == 0:
                 self.log_debug("Warning: No items were copied (maybe skipped all overwrites?).")
                 QMessageBox.warning(self, "Copy Warning", "No files were copied. Did you choose not to overwrite existing files?")
                 return

        except Exception as e:
            self.log_debug(f"Error during file copy: {e}")
            QMessageBox.critical(self, "File Copy Error", f"Failed to copy files to game directory: {e}")
            return

        # 4. Clean Up (Redundant now as we skip copying them, but keep just in case)
        self.log_debug("Double checking cleanup...")
        try:
            (game_dir / "!! EXTRACT ALL FILES TO GAME FOLDER !!").unlink(missing_ok=True)
            (game_dir / "_setup_windows.bat").unlink(missing_ok=True)
            (game_dir / "_setup_linux.sh").unlink(missing_ok=True) # Also remove linux setup script
            self.log_debug("Cleanup check complete.")
        except OSError as e:
            self.log_debug(f"Warning: Error during cleanup check: {e}")

        # 5. Filename Choice
        self.log_debug("Prompting for filename choice...")
        dll_options = ["dxgi.dll", "winmm.dll", "version.dll", "dbghelp.dll",
                       "d3d12.dll", "wininet.dll", "winhttp.dll", "OptiScaler.asi"]
        selected_filename, ok = QInputDialog.getItem(self, "Select OptiScaler Filename",
                                                    "Choose the DLL filename OptiScaler should use:",
                                                    dll_options, 0, False)

        if not ok or not selected_filename:
            self.log_debug("Enable aborted: User cancelled filename selection.")
            QMessageBox.warning(self, "Cancelled", "Filename selection cancelled. OptiScaler.dll was not renamed.")
            return

        self.log_debug(f"Selected filename: {selected_filename}")

        # 6. Rename OptiScaler.dll
        optiscaler_orig_path = game_dir / "OptiScaler.dll"
        optiscaler_new_path = game_dir / selected_filename
        self.log_debug(f"Attempting to rename {optiscaler_orig_path} to {optiscaler_new_path}")

        if str(optiscaler_orig_path) == str(optiscaler_new_path):
             self.log_debug("Original and target filenames are the same, skipping rename.")
        elif optiscaler_new_path.exists():
             reply = QMessageBox.question(self, "Confirm Overwrite",
                                         f"'{selected_filename}' already exists. Overwrite it with OptiScaler?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                         QMessageBox.StandardButton.Yes)
             if reply == QMessageBox.StandardButton.No:
                 self.log_debug("Rename cancelled due to existing file.")
                 QMessageBox.warning(self, "Rename Cancelled", f"'{selected_filename}' already exists. OptiScaler.dll was not renamed.")
                 return # Cancel the process
             else:
                 try:
                     optiscaler_new_path.unlink() # Remove existing before renaming
                     self.log_debug(f"Removed existing {selected_filename} before rename.")
                 except OSError as e:
                     self.log_debug(f"Error removing existing file before rename: {e}")
                     QMessageBox.critical(self, "Rename Error", f"Could not remove existing '{selected_filename}': {e}")
                     return

        # Perform the rename
        try:
            if optiscaler_orig_path.exists():
                 optiscaler_orig_path.rename(optiscaler_new_path)
                 self.log_debug("Rename successful.")
            else:
                 self.log_debug("Error: OptiScaler.dll not found in game directory after copy.")
                 QMessageBox.critical(self, "Rename Error", "OptiScaler.dll not found. Cannot rename.")
                 return
        except OSError as e:
            self.log_debug(f"Error during rename: {e}")
            QMessageBox.critical(self, "Rename Error", f"Failed to rename OptiScaler.dll: {e}")
            return

        # 7. Nvidia/DLSS Choice & Modify .ini
        self.log_debug("Checking Nvidia/DLSS preferences...")
        config_modified = False
        try:
            has_nvidia_smi = bool(shutil.which("nvidia-smi"))
            default_nvidia_answer = QMessageBox.StandardButton.Yes if has_nvidia_smi else QMessageBox.StandardButton.No
            default_nvidia_text = "Yes" if has_nvidia_smi else "No"
            nvidia_reply = QMessageBox.question(self, "Nvidia GPU?",
                                                f"Are you using an Nvidia GPU? (Auto-detect: {default_nvidia_text})",
                                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                default_nvidia_answer)

            if nvidia_reply == QMessageBox.StandardButton.No:
                self.log_debug("User indicated non-Nvidia GPU.")
                dlss_reply = QMessageBox.question(self, "Use DLSS Inputs?",
                                                  "Will you try to use DLSS inputs (enables spoofing)?\n"
                                                  "[Required for DLSS FG, Reflex->AL2]",
                                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                  QMessageBox.StandardButton.Yes)
                if dlss_reply == QMessageBox.StandardButton.No:
                    self.log_debug("User opted out of DLSS inputs. Disabling spoofing in .ini.")
                    ini_path = game_dir / "OptiScaler.ini"
                    if ini_path.exists():
                        try:
                            content = ini_path.read_text()
                            new_content = content.replace("Dxgi=auto", "Dxgi=false", 1)
                            if new_content != content:
                                ini_path.write_text(new_content)
                                self.log_debug("OptiScaler.ini modified: Dxgi set to false.")
                                config_modified = True
                            else: self.log_debug("Did not find 'Dxgi=auto' in OptiScaler.ini.")
                        except Exception as e:
                             self.log_debug(f"Error modifying OptiScaler.ini: {e}")
                             QMessageBox.warning(self, "Config Error", f"Could not modify OptiScaler.ini: {e}")
                    else:
                        self.log_debug("OptiScaler.ini not found, skipping modification.")
                        QMessageBox.warning(self, "Config Warning", "OptiScaler.ini not found.")
                else: self.log_debug("User opted in to DLSS inputs.")
            else: self.log_debug("User indicated Nvidia GPU.")
        except Exception as e:
             self.log_debug(f"Error during Nvidia/DLSS check or ini modification: {e}")
             QMessageBox.warning(self, "Configuration Error", f"An error occurred: {e}")

        # --- 8. REMOVED Registry Step ---

        # 9. Final Message
        self.log_debug("Enable process finished.")
        success_message = f"OptiScaler setup completed for this game!\nRenamed DLL: {selected_filename}\n"
        if config_modified: success_message += "Spoofing Disabled in OptiScaler.ini.\n"
        # Removed registry message
        success_message += "\nIMPORTANT:\nYou might need to add DLL overrides in game launch options (e.g., Steam).\n\n"
        success_message += f"Example: WINEDLLOVERRIDES={selected_filename}=n,b %COMMAND%"

        QMessageBox.information(self, "Setup Complete", success_message)


    def closeEvent(self, event):
        if self.download_thread and self.download_thread.isRunning():
            self.download_thread.cancel(); self.download_thread.wait()
        event.accept()

# --- Application Entry Point ---
if __name__ == '__main__':
    if not check_7z_command():
        print("Error: '7z' or '7zz' command not found.")
        print("Please install 'p7zip' and 'p7zip-plugins'.")
        try:
            app_check = QApplication.instance() or QApplication(sys.argv)
            error_box = QMessageBox(); error_box.setIcon(QMessageBox.Icon.Critical)
            error_box.setWindowTitle("Dependency Error"); error_box.setText("Command '7z'/'7zz' not found.")
            error_box.setInformativeText("Please install using:\n\nsudo dnf install p7zip p7zip-plugins\n")
            error_box.exec()
        except Exception: pass
        sys.exit(1)

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

