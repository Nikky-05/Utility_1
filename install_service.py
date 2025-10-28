import win32serviceutil
import win32service
import win32event
import servicemanager
import subprocess
import sys
import os
import time
import traceback

class TokenInfoService(win32serviceutil.ServiceFramework):
    _svc_name_ = "TokenInfoViewerService"
    _svc_display_name_ = "Token Info Viewer (Utility Replica)"
    _svc_description_ = "Auto-starts Utility Flask server for token detection."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.process = None
        self.log_file = os.path.join(os.path.dirname(__file__), "service_debug.log")

    def log(self, msg):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
            f.flush()

    def SvcStop(self):
        self.log("Service stopping...")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        try:
            if self.process:
                self.log("Terminating Flask process...")
                self.process.terminate()
                self.process.wait(timeout=10)
        except Exception as e:
            self.log(f"Error stopping process: {e}")
        win32event.SetEvent(self.hWaitStop)
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)
        self.log("Service stopped cleanly.")

    def SvcDoRun(self):
        self.log("Service starting...")
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)

        try:
            python_path = r"C:\Users\hp\Downloads\TokenInfo Viewer\TokenInfo Viewer\.venv\Scripts\python.exe"
            app_path = r"C:\Users\hp\Downloads\TokenInfo Viewer\TokenInfo Viewer\app.py"
            self.log(f"Launching Flask app: {python_path} {app_path}")

            # Launch Flask
            self.process = subprocess.Popen(
                [python_path, app_path],
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdout=open(self.log_file, "a"),
                stderr=subprocess.STDOUT,
            )

            self.log("Flask process launched, waiting to stabilize...")
            time.sleep(15)  # Give it time to start Flask

            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.log("Service is now RUNNING.")
        except Exception as e:
            err_msg = traceback.format_exc()
            self.log(f"Error during start: {err_msg}")
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)
            return

        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        self.log("Service loop ended.")


if __name__ == "__main__":
    with open(os.path.join(os.path.dirname(__file__), "service_debug.log"), "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] install_service invoked\n")
    win32serviceutil.HandleCommandLine(TokenInfoService)
