import enum
import ctypes


class MsgBox:
    # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#return-value
    class ReturnValues(enum.IntEnum):
        IDABORT = 3 # The Abort button was selected.
        IDCANCEL = 2 # The Cancel button was selected.
        IDCONTINUE = 11 # The Continue button was selected.
        IDIGNORE = 5 # The Ignore button was selected.
        IDNO = 7 # The No button was selected.
        IDOK = 1 # The OK button was selected.
        IDRETRY = 4 # The Retry button was selected.
        IDTRYAGAIN = 10 # The Try Again button was selected.
        IDYES = 6 # The Yes button was selected.

    class Style(enum.IntFlag):
        # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw
        # https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/msgbox-function
        OKOnly = 0  # Display OK button only.
        OKCancel = 1  # Display OK and Cancel buttons.
        AbortRetryIgnore = 2  # Display Abort, Retry, and Ignore buttons.
        YesNoCancel = 3  # Display Yes, No, and Cancel buttons.
        YesNo = 4  # Display Yes and No buttons.
        RetryCancel = 5  # Display Retry and Cancel buttons.
        Critical = 16  # Display Critical Message icon.
        Question = 32  # Display Warning Query icon.
        Exclamation = 48  # Display Warning Message icon.
        Information = 64  # Display Information Message icon.
        DefaultButton1 = 0  # First button is default.
        DefaultButton2 = 256  # Second button is default.
        DefaultButton3 = 512  # Third button is default.
        DefaultButton4 = 768  # Fourth button is default.
        ApplicationModal = 0  # Application modal; the user must respond to the message box before continuing work in the current application.
        SystemModal = 4096  # System modal; all applications are suspended until the user responds to the message box.
        MsgBoxHelpButton = 16384  # Adds Help button to the message box.
        MsgBoxSetForeground = 65536  # Specifies the message box window as the foreground window.
        MsgBoxRight = 524288  # Text is right-aligned.
        MsgBoxRtlReading = 1048576  # Specifies text should appear as right-to-left reading on Hebrew and Arabic systems.

    @staticmethod
    def show(title: str, message: str, style: Style):
        # https://stackoverflow.com/questions/50086178/python-how-to-keep-messageboxw-on-top-of-all-other-windows
        msgbox_result = ctypes.windll.user32.MessageBoxW(0, message, title, style)
        if not isinstance(msgbox_result, int):
            raise TypeError(f'Expected "int" object, got "{type(msgbox_result)}"')
        return msgbox_result
