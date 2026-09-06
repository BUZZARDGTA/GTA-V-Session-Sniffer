"""Toxic Commando menu and status label mixin for `MainWindow`."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QFont, QFontMetrics
from PySide6.QtWidgets import QLabel, QMainWindow, QMenu, QMenuBar, QWidgetAction

from session_sniffer.guis.stylesheets import GTA5_STATUS_LABEL_STYLESHEET
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings


class ToxicCommandoMixin(QMainWindow):
    """Toxic Commando menu and status label mixin for `MainWindow`."""

    _toxic_commando_menu: QMenu
    _toxic_commando_status_label: QLabel
    _toxic_commando_status_widget_action: QAction
    _last_toxic_commando_status_key: tuple[bool, bool, bool]

    def _build_toxic_commando_menu(self, menu_bar: QMenuBar) -> None:
        """Construct the Toxic Commando menu and its status widget."""
        toxic_commando_menu = menu_bar.addMenu('Toxic Commando')
        if not toxic_commando_menu:
            message = 'Failed to create Toxic Commando menu'
            raise RuntimeError(message)
        toxic_commando_menu.setToolTipsVisible(True)
        toxic_commando_menu_action = toxic_commando_menu.menuAction()
        if not toxic_commando_menu_action:
            message = 'Failed to get Toxic Commando menu action'
            raise RuntimeError(message)
        toxic_commando_menu_action.setVisible(Settings.is_toxic_commando_feature_set())
        self._toxic_commando_menu = toxic_commando_menu

        toxic_commando_status_label = QLabel()
        toxic_commando_status_label.setTextFormat(Qt.TextFormat.RichText)
        toxic_commando_status_label.setStyleSheet(GTA5_STATUS_LABEL_STYLESHEET)
        toxic_commando_status_label.setText('<span style="color: #f44336;">●</span> Toxic Commando not running')
        toxic_commando_status_label.setToolTip("John Carpenter's Toxic Commando process detection state")
        toxic_commando_status_widget_action = QWidgetAction(self)
        toxic_commando_status_widget_action.setDefaultWidget(toxic_commando_status_label)
        toxic_commando_menu.addAction(toxic_commando_status_widget_action)
        self._toxic_commando_status_label = toxic_commando_status_label
        self._toxic_commando_status_widget_action = toxic_commando_status_widget_action
        self._resize_toxic_commando_status_label('● Toxic Commando not running')

        toxic_commando_menu.aboutToShow.connect(self._update_toxic_commando_status_label)

        self._last_toxic_commando_status_key = (False, False, False)

    def _resize_toxic_commando_status_label(self, visible_text: str) -> None:
        """Resize the Toxic Commando status label to fit `visible_text`."""
        status_font = QFont(self._toxic_commando_status_label.font())
        status_font.setPointSize(10)
        self._toxic_commando_status_label.setMinimumWidth(QFontMetrics(status_font).horizontalAdvance(visible_text) + 44 + 12)

    def _update_toxic_commando_status_label(self) -> None:
        """Refresh the Toxic Commando status label and tooltip from cached `CaptureState` values."""
        if CaptureState.toxic_commando_is_running:
            path_tooltip = (
                str(CaptureState.toxic_commando_path)
                if CaptureState.toxic_commando_path is not None
                else "John Carpenter's Toxic Commando process detection state"
            )
            if CaptureState.toxic_commando_is_suspended:
                visible_text = 'Toxic Commando (Suspended)'
                self._toxic_commando_status_label.setText(f'<span style="color: #ff9800;">●</span> {visible_text}')
                self._toxic_commando_status_label.setToolTip(f'{path_tooltip}\nProcess is currently suspended')
            else:
                visible_text = 'Toxic Commando'
                self._toxic_commando_status_label.setText(f'<span style="color: #4caf50;">●</span> {visible_text}')
                self._toxic_commando_status_label.setToolTip(path_tooltip)
        else:
            visible_text = 'Toxic Commando not running'
            self._toxic_commando_status_label.setText('<span style="color: #f44336;">●</span> Toxic Commando not running')
            self._toxic_commando_status_label.setToolTip("John Carpenter's Toxic Commando process detection state")
        self._resize_toxic_commando_status_label(f'● {visible_text}')
        self._last_toxic_commando_status_key = (
            CaptureState.toxic_commando_is_running,
            CaptureState.toxic_commando_is_suspended,
            CaptureState.is_local_capture(),
        )

    def _sync_toxic_commando_status(self) -> None:
        """Update Toxic Commando status label if process status changed."""
        toxic_commando_status_key = (
            CaptureState.toxic_commando_is_running,
            CaptureState.toxic_commando_is_suspended,
            CaptureState.is_local_capture(),
        )
        if toxic_commando_status_key != self._last_toxic_commando_status_key:
            self._update_toxic_commando_status_label()
