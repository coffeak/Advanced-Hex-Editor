import sys
import binascii
import re
import struct
import hashlib
from collections import deque
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QTableView, QVBoxLayout, QWidget,
    QMessageBox, QLineEdit, QPushButton, QHBoxLayout, QLabel, QHeaderView,
    QStatusBar, QComboBox, QProgressBar, QSplitter, QDockWidget, QDialog,
    QDialogButtonBox, QTextEdit, QListWidget, QSpinBox, QCheckBox, QGroupBox,
    QRadioButton, QMenu, QToolBar, QInputDialog, QTabWidget, QStackedWidget
)
from PyQt6.QtCore import Qt, QAbstractTableModel, QByteArray, QSettings, QSize, QTimer
from PyQt6.QtGui import (
    QColor, QKeySequence, QShortcut, QTextCursor, QAction, QIcon,
    QStandardItemModel, QStandardItem, QFont, QFontMetrics
)


class HexTableModel(QAbstractTableModel):
    """Enhanced Hex Table Model with all requested features"""

    def __init__(self, file_path=None, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.data_cache = bytearray()
        self.file_size = 0
        self.modified = False

        # Undo/Redo system
        self.undo_stack = deque(maxlen=1000)
        self.redo_stack = deque()

        # Display settings
        self.edit_mode = 'hex'  # hex/dec/bin
        self.endianness = 'little'  # little/big
        self.byte_group_size = 1  # 1,2,4,8 bytes
        self.zoom_level = 100

        # Features
        self.bookmarks = set()
        self.highlighted_bytes = set()
        self.tbl_mapping = {}
        self.show_deleted = False
        self.deleted_bytes = set()

        # Display toggles
        self.show_hex = True
        self.show_ascii = True
        self.show_dec = False
        self.show_bin = False

        if self.file_path:
            self.load_file()

    def load_file(self):
        try:
            with open(self.file_path, "rb") as f:
                self.data_cache = bytearray(f.read())
                self.file_size = len(self.data_cache)
                self.modified = False
        except Exception as e:
            QMessageBox.critical(None, "Error", f"File loading error: {e}")

    def rowCount(self, parent=None):
        bytes_per_row = 16 // self.byte_group_size
        return (len(self.data_cache) // bytes_per_row) + (1 if len(self.data_cache) % bytes_per_row else 0)

    def columnCount(self, parent=None):
        # Dynamic column count based on visible columns
        columns = 1  # Offset column

        if self.show_hex:
            columns += (16 // self.byte_group_size)
        if self.show_ascii:
            columns += 1
        if self.show_dec:
            columns += (16 // self.byte_group_size)
        if self.show_bin:
            columns += (16 // self.byte_group_size)

        return columns

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row, col = index.row(), index.column()
        bytes_per_row = 16 // self.byte_group_size

        # Offset column (always column 0)
        if col == 0:
            if role == Qt.ItemDataRole.DisplayRole:
                return f"{row * 16:08X}"
            return None

        # Calculate which data column we're in
        data_col = col - 1  # Adjust for offset column

        # Determine which data type we're showing
        current_type = None
        type_start_col = 0

        if self.show_hex:
            if data_col < bytes_per_row:
                current_type = 'hex'
            type_start_col += bytes_per_row

        if not current_type and self.show_dec:
            if data_col < type_start_col + bytes_per_row:
                current_type = 'dec'
            type_start_col += bytes_per_row

        if not current_type and self.show_bin:
            if data_col < type_start_col + bytes_per_row:
                current_type = 'bin'
            type_start_col += bytes_per_row

        if not current_type and self.show_ascii:
            if data_col == type_start_col:
                current_type = 'ascii'

        if not current_type:
            return None

        # Data columns
        if current_type in ['hex', 'dec', 'bin']:
            # Calculate the actual byte position
            if current_type == 'hex':
                group_col = data_col
            elif current_type == 'dec':
                group_col = data_col - (bytes_per_row if self.show_hex else 0)
            elif current_type == 'bin':
                group_col = data_col - ((bytes_per_row if self.show_hex else 0) +
                                        (bytes_per_row if self.show_dec else 0))

            start = row * 16 + group_col * self.byte_group_size
            end = min(start + self.byte_group_size, len(self.data_cache))

            if start >= len(self.data_cache):
                return ""

            data = self.data_cache[start:end]

            # Highlighting
            if role == Qt.ItemDataRole.BackgroundRole:
                if any(start <= i < end for i in self.highlighted_bytes):
                    return QColor(Qt.GlobalColor.yellow)
                if any(start <= i < end for i in self.deleted_bytes) and self.show_deleted:
                    return QColor(255, 200, 200)
                return None

            # Display text
            if role == Qt.ItemDataRole.DisplayRole:
                if current_type == 'hex':
                    if self.byte_group_size == 1:
                        return ' '.join(f"{b:02X}" for b in data)
                    else:
                        return data.hex(' ').upper()
                elif current_type == 'dec':
                    if self.byte_group_size == 1:
                        return ' '.join(f"{b:3}" for b in data)
                    else:
                        val = int.from_bytes(data, self.endianness)
                        return str(val)
                elif current_type == 'bin':
                    if self.byte_group_size == 1:
                        return ' '.join(bin(b)[2:].zfill(8) for b in data)
                    else:
                        val = int.from_bytes(data, self.endianness)
                        return bin(val)[2:].zfill(8 * self.byte_group_size)
            return None

        # ASCII column
        elif current_type == 'ascii':
            if role == Qt.ItemDataRole.DisplayRole:
                start = row * 16
                end = min(start + 16, len(self.data_cache))
                ascii_str = ""
                for i in range(start, end):
                    if i in self.deleted_bytes and not self.show_deleted:
                        continue
                    byte = self.data_cache[i]
                    if byte in self.tbl_mapping:
                        ascii_str += self.tbl_mapping[byte]
                    elif 32 <= byte < 127:
                        ascii_str += chr(byte)
                    else:
                        ascii_str += "."
                return ascii_str
            return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if orientation == Qt.Orientation.Horizontal:
            if section == 0:
                return "Offset"

            # Calculate which data column we're in
            data_col = section - 1
            bytes_per_row = 16 // self.byte_group_size

            # Determine which data type we're showing
            current_type = None
            type_start_col = 0

            if self.show_hex:
                if data_col < bytes_per_row:
                    current_type = 'hex'
                type_start_col += bytes_per_row

            if not current_type and self.show_dec:
                if data_col < type_start_col + bytes_per_row:
                    current_type = 'dec'
                type_start_col += bytes_per_row

            if not current_type and self.show_bin:
                if data_col < type_start_col + bytes_per_row:
                    current_type = 'bin'
                type_start_col += bytes_per_row

            if not current_type and self.show_ascii:
                if data_col == type_start_col:
                    current_type = 'ascii'

            if current_type:
                return current_type.upper()

        return None

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid() or role != Qt.ItemDataRole.EditRole:
            return False

        row, col = index.row(), index.column()
        bytes_per_row = 16 // self.byte_group_size

        # Only allow editing in hex columns
        if not (col > 0 and (self.show_hex and (col - 1) < bytes_per_row)):
            return False

        group_col = col - 1
        start = row * 16 + group_col * self.byte_group_size
        end = start + self.byte_group_size

        # Save old value for undo
        old_data = bytes(self.data_cache[start:end])

        try:
            if self.edit_mode == 'hex':
                hex_str = value.replace(" ", "")
                new_data = bytes.fromhex(hex_str)
            elif self.edit_mode == 'dec':
                num = int(value)
                new_data = num.to_bytes(self.byte_group_size, self.endianness)
            elif self.edit_mode == 'bin':
                num = int(value, 2)
                new_data = num.to_bytes(self.byte_group_size, self.endianness)

            # Check size
            if len(new_data) != self.byte_group_size:
                return False

            # Apply change
            self.data_cache[start:end] = new_data
            self.modified = True

            # Push to undo stack
            self.undo_stack.append(('edit', start, old_data, new_data))
            self.redo_stack.clear()

            self.dataChanged.emit(index, index)
            return True

        except (ValueError, struct.error):
            return False

    def flags(self, index):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        col = index.column()
        bytes_per_row = 16 // self.byte_group_size

        flags = Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled

        # Only allow editing in hex columns
        if col > 0 and (self.show_hex and (col - 1) < bytes_per_row):
            flags |= Qt.ItemFlag.ItemIsEditable

        return flags

    def toggle_data_display(self, display_type, visible):
        """Toggle visibility of different data displays"""
        if display_type == 'hex':
            self.show_hex = visible
        elif display_type == 'ascii':
            self.show_ascii = visible
        elif display_type == 'dec':
            self.show_dec = visible
        elif display_type == 'bin':
            self.show_bin = visible

        self.layoutChanged.emit()

    def set_edit_mode(self, mode):
        self.edit_mode = mode
        self.layoutChanged.emit()

    def set_endianness(self, endian):
        self.endianness = endian
        self.layoutChanged.emit()

    def set_byte_group_size(self, size):
        self.byte_group_size = size
        self.layoutChanged.emit()

    def set_zoom_level(self, level):
        self.zoom_level = level
        font = QFont("Courier New")
        font.setPointSize(level / 10)
        self.layoutChanged.emit()

    def toggle_bookmark(self, offset):
        if offset in self.bookmarks:
            self.bookmarks.remove(offset)
        else:
            self.bookmarks.add(offset)
        self.layoutChanged.emit()

    def highlight_bytes(self, offsets):
        self.highlighted_bytes = set(offsets)
        self.layoutChanged.emit()

    def load_tbl_file(self, path):
        self.tbl_mapping.clear()
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    if '=' in line:
                        hex_val, char = line.split('=', 1)
                        self.tbl_mapping[int(hex_val.strip(), 16)] = char.strip()
            self.layoutChanged.emit()
            return True
        except Exception as e:
            QMessageBox.critical(None, "Error", f"Failed to load TBL file: {e}")
            return False

    def undo(self):
        if self.undo_stack:
            action = self.undo_stack.pop()
            if action[0] == 'edit':
                _, offset, old_data, _ = action
                self.data_cache[offset:offset + len(old_data)] = old_data
                self.redo_stack.append(action)
                self.layoutChanged.emit()
                return True
        return False

    def redo(self):
        if self.redo_stack:
            action = self.redo_stack.pop()
            if action[0] == 'edit':
                _, offset, _, new_data = action
                self.data_cache[offset:offset + len(new_data)] = new_data
                self.undo_stack.append(action)
                self.layoutChanged.emit()
                return True
        return False

    def delete_bytes(self, offsets):
        old_values = [(i, bytes([self.data_cache[i]])) for i in offsets]
        for i in offsets:
            self.deleted_bytes.add(i)
        self.undo_stack.append(('delete', old_values))
        self.redo_stack.clear()
        self.modified = True
        self.layoutChanged.emit()

    def restore_bytes(self, offsets):
        for i in offsets:
            self.deleted_bytes.discard(i)
        self.modified = True
        self.layoutChanged.emit()


class DisplaySettingsDialog(QDialog):
    def __init__(self, model, parent=None):
        super().__init__(parent)
        self.model = model
        self.setWindowTitle("Display Settings")
        self.setModal(True)

        layout = QVBoxLayout()

        # Data display group
        display_group = QGroupBox("Data Display")
        display_layout = QVBoxLayout()

        self.hex_check = QCheckBox("Show Hex")
        self.hex_check.setChecked(self.model.show_hex)

        self.ascii_check = QCheckBox("Show ASCII")
        self.ascii_check.setChecked(self.model.show_ascii)

        self.dec_check = QCheckBox("Show Decimal")
        self.dec_check.setChecked(self.model.show_dec)

        self.bin_check = QCheckBox("Show Binary")
        self.bin_check.setChecked(self.model.show_bin)

        display_layout.addWidget(self.hex_check)
        display_layout.addWidget(self.ascii_check)
        display_layout.addWidget(self.dec_check)
        display_layout.addWidget(self.bin_check)
        display_group.setLayout(display_layout)

        # Byte grouping
        group_group = QGroupBox("Byte Grouping")
        group_layout = QVBoxLayout()

        self.group_size = QComboBox()
        self.group_size.addItems(["1 byte", "2 bytes (word)", "4 bytes (dword)", "8 bytes (qword)"])
        self.group_size.setCurrentIndex([1, 2, 4, 8].index(self.model.byte_group_size))

        self.endianness = QComboBox()
        self.endianness.addItems(["Little Endian", "Big Endian"])
        self.endianness.setCurrentIndex(0 if self.model.endianness == 'little' else 1)

        group_layout.addWidget(QLabel("Group Size:"))
        group_layout.addWidget(self.group_size)
        group_layout.addWidget(QLabel("Endianness:"))
        group_layout.addWidget(self.endianness)
        group_group.setLayout(group_layout)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        # Layout
        layout.addWidget(display_group)
        layout.addWidget(group_group)
        layout.addWidget(button_box)
        self.setLayout(layout)

    def accept(self):
        # Update display settings
        self.model.toggle_data_display('hex', self.hex_check.isChecked())
        self.model.toggle_data_display('ascii', self.ascii_check.isChecked())
        self.model.toggle_data_display('dec', self.dec_check.isChecked())
        self.model.toggle_data_display('bin', self.bin_check.isChecked())

        # Update byte grouping
        group_sizes = [1, 2, 4, 8]
        self.model.set_byte_group_size(group_sizes[self.group_size.currentIndex()])

        # Update endianness
        self.model.set_endianness('little' if self.endianness.currentIndex() == 0 else 'big')

        super().accept()


class FindReplaceDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Find/Replace")
        self.setMinimumSize(400, 300)

        layout = QVBoxLayout()

        # Find section
        find_group = QGroupBox("Find")
        find_layout = QVBoxLayout()

        self.find_text = QLineEdit()
        self.find_hex = QCheckBox("Hex Value")
        self.find_regex = QCheckBox("Regular Expression")
        self.find_case = QCheckBox("Case Sensitive")

        find_layout.addWidget(QLabel("Find what:"))
        find_layout.addWidget(self.find_text)
        find_layout.addWidget(self.find_hex)
        find_layout.addWidget(self.find_regex)
        find_layout.addWidget(self.find_case)
        find_group.setLayout(find_layout)

        # Replace section
        replace_group = QGroupBox("Replace")
        replace_layout = QVBoxLayout()

        self.replace_text = QLineEdit()
        self.replace_hex = QCheckBox("Hex Value")

        replace_layout.addWidget(QLabel("Replace with:"))
        replace_layout.addWidget(self.replace_text)
        replace_layout.addWidget(self.replace_hex)
        replace_group.setLayout(replace_layout)

        # Buttons
        button_box = QDialogButtonBox()
        self.find_next_btn = button_box.addButton("Find Next", QDialogButtonBox.ButtonRole.ActionRole)
        self.find_all_btn = button_box.addButton("Find All", QDialogButtonBox.ButtonRole.ActionRole)
        self.replace_btn = button_box.addButton("Replace", QDialogButtonBox.ButtonRole.ActionRole)
        self.replace_all_btn = button_box.addButton("Replace All", QDialogButtonBox.ButtonRole.ActionRole)
        button_box.addButton(QDialogButtonBox.StandardButton.Close)

        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        # Layout assembly
        layout.addWidget(find_group)
        layout.addWidget(replace_group)
        layout.addWidget(button_box)
        self.setLayout(layout)

        # Connections
        self.find_next_btn.clicked.connect(self.find_next)
        self.find_all_btn.clicked.connect(self.find_all)
        self.replace_btn.clicked.connect(self.replace)
        self.replace_all_btn.clicked.connect(self.replace_all)

    def find_next(self):
        text = self.find_text.text()
        hex_mode = self.find_hex.isChecked()
        regex_mode = self.find_regex.isChecked()
        case_sensitive = self.find_case.isChecked()

        if not text:
            return

        editor = self.parent()
        if hex_mode:
            try:
                pattern = bytes.fromhex(text.replace(" ", ""))
            except ValueError:
                QMessageBox.warning(self, "Error", "Invalid hex string")
                return
        else:
            pattern = text.encode('utf-8')

        # Implement search logic...
        editor.model.highlight_bytes([0])  # Example

    def find_all(self):
        pass

    def replace(self):
        pass

    def replace_all(self):
        pass

class HexEditor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Hex Editor")
        self.setGeometry(100, 100, 1200, 800)

        # Initialize model and views
        self.model = HexTableModel()

        # Settings
        self.settings = QSettings("HexEditor", "AdvancedHexEditor")

        # Initialize recent files system
        self.recent_files = []
        self.recent_files_menu = None

        # Initialize UI components in correct order
        self.init_actions()
        self.init_recent_files()  # Must come before init_menu()
        self.init_docking()
        self.init_menu()  # Now recent_files_menu exists
        self.init_toolbar()
        self.init_shortcuts()
        self.init_ui()

        self.load_settings()

    def init_recent_files(self):
        """Initialize recent files menu"""
        self.recent_files = self.settings.value("recentFiles", [])
        self.recent_files_menu = QMenu("&Recent Files", self)  # Create the menu
        self.update_recent_files_menu()

    def init_ui(self):
        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Main layout
        self.main_layout = QVBoxLayout(self.central_widget)

        # Toolbar area
        self.toolbar_layout = QHBoxLayout()
        self.main_layout.addLayout(self.toolbar_layout)

        # Hex view
        self.hex_view = QTableView()
        self.hex_view.setModel(self.model)
        self.hex_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.hex_view.verticalHeader().setDefaultSectionSize(20)

        # Set monospace font
        font = QFont("Courier New")
        font.setPointSize(10)
        self.hex_view.setFont(font)

        # Add to main layout
        self.main_layout.addWidget(self.hex_view)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.update_status()

    def init_docking(self):
        """Initialize docking panels with toggleable displays"""
        # 1. Bookmarks panel
        self.bookmark_dock = QDockWidget("Bookmarks", self)
        self.bookmark_dock.setObjectName("bookmarkDock")

        # Create a container widget with layout
        bookmark_container = QWidget()
        bookmark_layout = QVBoxLayout(bookmark_container)

        # Add controls for display options
        display_group = QGroupBox("Display Options")
        display_layout = QVBoxLayout()

        self.bm_hex_check = QCheckBox("Show Hex")
        self.bm_hex_check.setChecked(True)
        self.bm_hex_check.stateChanged.connect(self.update_bookmark_display)

        self.bm_ascii_check = QCheckBox("Show ASCII")
        self.bm_ascii_check.setChecked(True)
        self.bm_ascii_check.stateChanged.connect(self.update_bookmark_display)

        self.bm_dec_check = QCheckBox("Show Decimal")
        self.bm_dec_check.stateChanged.connect(self.update_bookmark_display)

        self.bm_bin_check = QCheckBox("Show Binary")
        self.bm_bin_check.stateChanged.connect(self.update_bookmark_display)

        display_layout.addWidget(self.bm_hex_check)
        display_layout.addWidget(self.bm_ascii_check)
        display_layout.addWidget(self.bm_dec_check)
        display_layout.addWidget(self.bm_bin_check)
        display_group.setLayout(display_layout)

        # Add list widget for bookmarks
        self.bookmark_list = QListWidget()
        self.bookmark_list.itemDoubleClicked.connect(self.go_to_bookmark)

        bookmark_layout.addWidget(display_group)
        bookmark_layout.addWidget(self.bookmark_list)
        bookmark_container.setLayout(bookmark_layout)

        self.bookmark_dock.setWidget(bookmark_container)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.bookmark_dock)

        # 2. Properties panel
        self.properties_dock = QDockWidget("Properties", self)
        self.properties_dock.setObjectName("propertiesDock")

        # Create a container widget with layout
        properties_container = QWidget()
        properties_layout = QVBoxLayout(properties_container)

        # Add tabs for different property views
        self.property_tabs = QTabWidget()

        # Hex view tab
        self.hex_property_view = QTextEdit()
        self.hex_property_view.setReadOnly(True)
        self.hex_property_view.setFont(QFont("Courier New"))
        self.property_tabs.addTab(self.hex_property_view, "Hex")

        # ASCII view tab
        self.ascii_property_view = QTextEdit()
        self.ascii_property_view.setReadOnly(True)
        self.ascii_property_view.setFont(QFont("Courier New"))
        self.property_tabs.addTab(self.ascii_property_view, "ASCII")

        # Decimal view tab
        self.dec_property_view = QTextEdit()
        self.dec_property_view.setReadOnly(True)
        self.dec_property_view.setFont(QFont("Courier New"))
        self.property_tabs.addTab(self.dec_property_view, "Decimal")

        # Binary view tab
        self.bin_property_view = QTextEdit()
        self.bin_property_view.setReadOnly(True)
        self.bin_property_view.setFont(QFont("Courier New"))
        self.property_tabs.addTab(self.bin_property_view, "Binary")

        properties_layout.addWidget(self.property_tabs)
        properties_container.setLayout(properties_layout)

        self.properties_dock.setWidget(properties_container)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.properties_dock)

        # 3. Set dock properties
        self.setDockOptions(
            QMainWindow.DockOption.AllowNestedDocks |
            QMainWindow.DockOption.AllowTabbedDocks
        )

        # Timer for updating property views
        self.property_update_timer = QTimer(self)
        self.property_update_timer.setInterval(500)  # Update every 500ms
        self.property_update_timer.timeout.connect(self.update_property_views)
        self.property_update_timer.start()

    def init_recent_files(self):
        """Initialize recent files menu"""
        self.recent_files = self.settings.value("recentFiles", [])
        self.recent_files_menu = self.menuBar().addMenu("&Recent Files")
        self.update_recent_files_menu()

    def update_recent_files_menu(self):
        """Update the recent files menu"""
        self.recent_files_menu.clear()
        for i, file_path in enumerate(self.recent_files[:5]):
            action = QAction(f"{i + 1}. {file_path}", self)
            action.triggered.connect(lambda checked, path=file_path: self.open_recent_file(path))
            self.recent_files_menu.addAction(action)
        self.recent_files_menu.addSeparator()
        clear_action = QAction("Clear Menu", self)
        clear_action.triggered.connect(self.clear_recent_files)
        self.recent_files_menu.addAction(clear_action)

    def open_recent_file(self, path):
        """Open a file from recent files list"""
        try:
            self.model = HexTableModel(path)
            self.hex_view.setModel(self.model)
            self.update_status()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not open file: {e}")

    def clear_recent_files(self):
        """Clear recent files list"""
        self.recent_files = []
        self.settings.setValue("recentFiles", self.recent_files)
        self.update_recent_files_menu()

    def add_recent_file(self, path):
        """Add a file to recent files list"""
        if path in self.recent_files:
            self.recent_files.remove(path)
        self.recent_files.insert(0, path)
        self.recent_files = self.recent_files[:10]  # Keep only 10 most recent
        self.settings.setValue("recentFiles", self.recent_files)
        self.update_recent_files_menu()

    def update_bookmark_display(self):
        """Update how bookmarks are displayed based on checkbox states"""
        self.bookmark_list.clear()
        for offset in sorted(self.model.bookmarks):
            if offset < len(self.model.data_cache):
                byte = self.model.data_cache[offset]
                items = []

                if self.bm_hex_check.isChecked():
                    items.append(f"0x{byte:02X}")

                if self.bm_dec_check.isChecked():
                    items.append(f"{byte:3}")

                if self.bm_bin_check.isChecked():
                    items.append(bin(byte)[2:].zfill(8))

                if self.bm_ascii_check.isChecked():
                    char = chr(byte) if 32 <= byte < 127 else '.'
                    items.append(f"'{char}'")

                text = f"{offset:08X}: " + ' | '.join(items)
                self.bookmark_list.addItem(text)

    def update_property_views(self):
        """Update the property views with current selection"""
        selection = self.hex_view.selectionModel().selectedIndexes()
        if not selection:
            return

        # Get selected data
        data = bytearray()
        for index in selection:
            if index.column() == 0:  # Skip offset column
                continue

            pos = index.row() * 16 + (index.column() - 1)
            if pos < len(self.model.data_cache):
                data.append(self.model.data_cache[pos])

        if not data:
            return

        # Update hex view
        hex_text = ' '.join(f"{b:02X}" for b in data)
        self.hex_property_view.setPlainText(hex_text)

        # Update ASCII view
        ascii_text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        self.ascii_property_view.setPlainText(ascii_text)

        # Update decimal view
        dec_text = ' '.join(str(b) for b in data)
        self.dec_property_view.setPlainText(dec_text)

        # Update binary view
        bin_text = ' '.join(bin(b)[2:].zfill(8) for b in data)
        self.bin_property_view.setPlainText(bin_text)

    def go_to_bookmark(self, item):
        """Navigate to a bookmarked location"""
        text = item.text()
        try:
            offset = int(text.split(':')[0], 16)
            row = offset // 16
            col = (offset % 16) + 1  # +1 for offset column

            # Scroll to the position
            index = self.model.index(row, col)
            self.hex_view.scrollTo(index, QTableView.ScrollHint.PositionAtCenter)
            self.hex_view.selectRow(row)

            # Highlight the byte
            self.model.highlight_bytes([offset])
        except ValueError:
            pass

    def init_actions(self):
        # File actions
        self.open_action = QAction("&Open", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.triggered.connect(self.open_file)

        self.save_action = QAction("&Save", self)
        self.save_action.setShortcut(QKeySequence.StandardKey.Save)
        self.save_action.triggered.connect(self.save_file)

        self.save_as_action = QAction("Save &As...", self)
        self.save_as_action.triggered.connect(self.save_file_as)

        # Edit actions
        self.undo_action = QAction("&Undo", self)
        self.undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        self.undo_action.triggered.connect(self.model.undo)

        self.redo_action = QAction("&Redo", self)
        self.redo_action.setShortcut(QKeySequence.StandardKey.Redo)
        self.redo_action.triggered.connect(self.model.redo)

        self.find_action = QAction("&Find/Replace", self)
        self.find_action.setShortcut(QKeySequence.StandardKey.Find)
        self.find_action.triggered.connect(self.show_find_dialog)

        # View actions
        self.zoom_in_action = QAction("Zoom &In", self)
        self.zoom_in_action.setShortcut(QKeySequence.StandardKey.ZoomIn)
        self.zoom_in_action.triggered.connect(self.zoom_in)

        self.zoom_out_action = QAction("Zoom &Out", self)
        self.zoom_out_action.setShortcut(QKeySequence.StandardKey.ZoomOut)
        self.zoom_out_action.triggered.connect(self.zoom_out)

        # Display settings action
        self.display_settings_action = QAction("&Display Settings", self)
        self.display_settings_action.triggered.connect(self.show_display_settings)

        # Bookmark actions
        self.add_bookmark_action = QAction("&Add Bookmark", self)
        self.add_bookmark_action.setShortcut("Ctrl+B")
        self.add_bookmark_action.triggered.connect(self.add_bookmark)

    def init_menu(self):
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")
        file_menu.addAction(self.open_action)
        file_menu.addAction(self.save_action)
        file_menu.addAction(self.save_as_action)
        file_menu.addSeparator()
        file_menu.addMenu(self.recent_files_menu)

        # Edit menu
        edit_menu = menubar.addMenu("&Edit")
        edit_menu.addAction(self.undo_action)
        edit_menu.addAction(self.redo_action)
        edit_menu.addSeparator()
        edit_menu.addAction(self.find_action)

        # View menu
        view_menu = menubar.addMenu("&View")
        view_menu.addAction(self.zoom_in_action)
        view_menu.addAction(self.zoom_out_action)
        view_menu.addSeparator()
        view_menu.addAction(self.display_settings_action)
        view_menu.addSeparator()
        view_menu.addAction(self.bookmark_dock.toggleViewAction())
        view_menu.addAction(self.properties_dock.toggleViewAction())

        # Bookmarks menu
        bookmark_menu = menubar.addMenu("&Bookmarks")
        bookmark_menu.addAction(self.add_bookmark_action)

    def init_toolbar(self):
        toolbar = self.addToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(16, 16))

        toolbar.addAction(self.open_action)
        toolbar.addAction(self.save_action)
        toolbar.addSeparator()
        toolbar.addAction(self.undo_action)
        toolbar.addAction(self.redo_action)
        toolbar.addSeparator()
        toolbar.addAction(self.find_action)
        toolbar.addSeparator()
        toolbar.addAction(self.display_settings_action)

    def init_shortcuts(self):
        # Copy as...
        self.copy_as_shortcut = QShortcut(QKeySequence("Ctrl+Shift+C"), self)
        self.copy_as_shortcut.activated.connect(self.show_copy_as_dialog)

    def show_display_settings(self):
        dialog = DisplaySettingsDialog(self.model, self)
        dialog.exec()

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open File")
        if path:
            try:
                self.model = HexTableModel(path)
                self.hex_view.setModel(self.model)
                self.add_recent_file(path)
                self.update_status()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not open file: {e}")

    def save_file(self):
        if not self.model.file_path:
            self.save_file_as()
            return

        try:
            with open(self.model.file_path, "wb") as f:
                f.write(self.model.data_cache)
            self.model.modified = False
            self.update_status()
            QMessageBox.information(self, "Success", "File saved successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save file: {e}")

    def save_file_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save File")
        if path:
            self.model.file_path = path
            self.save_file()

    def show_find_dialog(self):
        dialog = FindReplaceDialog(self)
        dialog.exec()

    def show_copy_as_dialog(self):
        languages = ["C", "C++", "C#", "Java", "Python", "JavaScript", "Go", "Rust"]
        lang, ok = QInputDialog.getItem(self, "Copy As", "Select language:", languages, 0, False)
        if ok and lang:
            self.copy_as(lang)

    def copy_as(self, language):
        selection = self.get_selected_bytes()
        if not selection:
            return

        if language == "C":
            code = "unsigned char data[] = { " + ", ".join(f"0x{b:02X}" for b in selection) + " };"
        elif language == "C++":
            code = "std::vector<uint8_t> data = { " + ", ".join(f"0x{b:02X}" for b in selection) + " };"
        elif language == "C#":
            code = "byte[] data = new byte[] { " + ", ".join(f"0x{b:02X}" for b in selection) + " };"
        elif language == "Java":
            code = "byte[] data = { " + ", ".join(f"(byte)0x{b:02X}" for b in selection) + " };"
        elif language == "Python":
            code = "data = bytes([ " + ", ".join(f"0x{b:02X}" for b in selection) + " ])"
        elif language == "JavaScript":
            code = "const data = new Uint8Array([ " + ", ".join(f"0x{b:02X}" for b in selection) + " ]);"
        elif language == "Go":
            code = "data := []byte{ " + ", ".join(f"0x{b:02X}" for b in selection) + " }"
        elif language == "Rust":
            code = "let data: [u8; {}] = [ ".format(len(selection)) + ", ".join(f"0x{b:02X}" for b in selection) + " ];"

        clipboard = QApplication.clipboard()
        clipboard.setText(code)

    def add_bookmark(self):
        """Add bookmark at current selection"""
        selection = self.hex_view.selectionModel().selectedIndexes()
        if not selection:
            return

        # Get first selected byte offset
        index = selection[0]
        if index.column() == 0:  # Skip offset column
            return

        offset = index.row() * 16 + (index.column() - 1)
        self.model.toggle_bookmark(offset)
        self.update_bookmark_display()

    def get_selected_bytes(self):
        selection = self.hex_view.selectionModel()
        if not selection.hasSelection():
            return []

        indexes = selection.selectedIndexes()
        if not indexes:
            return []

        # Get selected bytes
        bytes = []
        for index in indexes:
            if index.column() == 0:  # Skip offset column
                continue

            row = index.row()
            col = index.column()
            byte_pos = row * 16 + (col - 1)

            if byte_pos < len(self.model.data_cache):
                bytes.append(self.model.data_cache[byte_pos])

        return bytes

    def zoom_in(self):
        self.model.set_zoom_level(min(200, self.model.zoom_level + 10))

    def zoom_out(self):
        self.model.set_zoom_level(max(50, self.model.zoom_level - 10))

    def update_status(self):
        status = []
        if self.model.file_path:
            status.append(f"File: {self.model.file_path}")
            status.append(f"Size: {self.model.file_size:,} bytes")
            status.append(f"Modified: {'Yes' if self.model.modified else 'No'}")

            # Show current position if selection
            selection = self.hex_view.selectionModel().selectedIndexes()
            if selection:
                index = selection[0]
                offset = index.row() * 16 + (index.column() - 1 if index.column() > 0 else 0)
                status.append(f"Position: 0x{offset:X} ({offset})")
        else:
            status.append("No file open")

        self.status_bar.showMessage(" | ".join(status))

    def load_settings(self):
        # Restore window geometry and state
        geometry = self.settings.value("windowGeometry")
        if geometry is not None:
            self.restoreGeometry(geometry)

        state = self.settings.value("windowState")
        if state is not None:
            self.restoreState(state)

        # Restore dock widget visibility
        self.bookmark_dock.setVisible(self.settings.value("bookmarkDockVisible", True, type=bool))
        self.properties_dock.setVisible(self.settings.value("propertiesDockVisible", True, type=bool))

    def save_settings(self):
        self.settings.setValue("windowGeometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
        self.settings.setValue("bookmarkDockVisible", self.bookmark_dock.isVisible())
        self.settings.setValue("propertiesDockVisible", self.properties_dock.isVisible())

    def closeEvent(self, event):
        if self.model.modified:
            reply = QMessageBox.question(
                self, 'Unsaved Changes',
                "You have unsaved changes. Do you want to save before exiting?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.save_file()
            elif reply == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return

        self.save_settings()
        super().closeEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    editor = HexEditor()
    editor.show()
    sys.exit(app.exec())