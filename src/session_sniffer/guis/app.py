"""Central QApplication instance for the entire application.

This module ensures there's only one QApplication instance throughout the application.
"""

import os
import sys

from PySide6.QtCore import QMessageLogContext, QtMsgType, qInstallMessageHandler
from PySide6.QtWidgets import QApplication

from session_sniffer.guis.theme import get_dark_palette


def _qt_message_handler(message_type: QtMsgType, _context: QMessageLogContext, message: str) -> None:
    if 'Portal operation not allowed' in message or 'QFileSystemWatcher: FindNextChangeNotification failed' in message:
        return
    if message_type in (QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
        sys.stderr.write(f'{message}\n')
    else:
        sys.stdout.write(f'{message}\n')


def _configure_platform_qt_environment() -> None:
    if sys.platform != 'win32':
        existing_logging_rules: str = os.environ.get('QT_LOGGING_RULES', '')
        suppression_rule: str = 'qt.qpa.theme.gnome=false'
        os.environ['QT_LOGGING_RULES'] = f'{existing_logging_rules};{suppression_rule}' if existing_logging_rules else suppression_rule
        # On Wayland, use bradient decorations so window controls (minimize, maximize, close)
        # and dark title bars render reliably without relying on desktop portal D-Bus queries.
        os.environ.setdefault('QT_WAYLAND_DECORATION', 'bradient')

    qInstallMessageHandler(_qt_message_handler)


_configure_platform_qt_environment()

# Create the single QApplication instance for the entire application.
# The stylesheet is applied later in main() after the screen size and UI scale
# factor are resolved, so fonts and sizes are correct for every display tier.
app = QApplication([])  # Passing an empty list for application arguments
app.setPalette(get_dark_palette())
