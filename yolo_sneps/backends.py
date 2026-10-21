"""Ways to run SNePSLOG statements through SNePS.

Each backend's run(statements, query) asserts the statements into an empty KB, asks the query,
and returns (answer_lines, errors), where errors is a list of (statement or None, message).
A non-empty error list means the answer may be incomplete.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .snepslog import check_statement


def _split_checked(statements):
    """Statements safe to send, and (statement, reason) for the ones that are not."""
    good, bad = [], []
    for statement in statements:
        problem = check_statement(statement)
        if problem:
            bad.append((statement, problem))
        else:
            good.append(statement)
    return good, bad


class SnepspacyBackend:
    """SNePS through SNePSpaCy's sneps_wrapper (pexpect, so Linux or WSL only).

    `snepspacy_dir` is a SNePSpaCy checkout; its bundled Sneps-Linux-Exe-2.7.0 is a 32-bit
    build, so a 64-bit Ubuntu/WSL needs `sudo apt install libc6-i386`. `timeout` applies to
    each call into SNePS (each assertion and the query), not to the whole image.
    """

    def __init__(self, snepspacy_dir, timeout=300):
        if sys.platform == "win32":
            raise RuntimeError("the snepspacy backend needs Linux or WSL (pexpect.spawn); "
                               "on Windows use the allegro backend")
        root = Path(snepspacy_dir).resolve()
        # Load by path: YOLO-KRR has its own (older) sneps_wrapper package that would shadow it.
        spec = importlib.util.spec_from_file_location(
            "snepspacy_sneps_api", root / "sneps_wrapper" / "sneps_api.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.api = self.module.sneps_api(directory=str(root / "Sneps-Linux-Exe-2.7.0"),
                                         enable_logging=False)
        self.timeout = timeout
        self.started = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.started:
            self.api.terminate()

    def run(self, statements, query):
        if self.started:
            self.api.clear_kb()
        else:
            self.api.init()  # starts SNePSLOG and clears the KB
            self.started = True
        self.api.process.timeout = self.timeout
        good, errors = _split_checked(statements)
        for statement in good:
            try:
                self.api.inform(statement)
            except (self.module.SnepsApiError, ValueError) as e:
                errors.append((statement, str(e)))
        try:
            return self.api.ask(query), errors
        except self.module.SnepsApiError as e:
            return [], errors + [(f"ask({query})", str(e))]


class AllegroBatchBackend:
    """The Windows SNePS 2.7 build, run headless.

    Its REPL lives in a GUI console window that cannot be driven over stdin/stdout, so this
    starts Sneps-2.7.exe with a generated Lisp driver that feeds SNePSLOG to the REPL through
    string streams and writes the transcript to a file.
    """

    # A rejected statement signals a Lisp error that ends the REPL; the driver reports it and
    # re-enters the REPL on the same stream so the remaining statements and the query still run.
    # Anything failing outside that loop exits with code 2 instead of waiting in the debugger.
    _DRIVER = """\
(handler-case
    (let* ((in (make-string-input-stream {text}))
           (out (with-output-to-string (o)
                  (let* ((io (make-two-way-stream in o))
                         (*standard-input* in) (*standard-output* o) (*terminal-io* io)
                         (*query-io* io) (*debug-io* io) (*error-output* o) (*trace-output* o))
                    (mp:with-timeout ({secs} (format o "~%<<TIMEOUT>>~%"))
                      (loop (handler-case (progn (sneps:snepslog :inunit in :outunit o) (return))
                              (error (e)
                                (format o "~%<<LISP ERROR: ~a>>~%" e)
                                (unless (peek-char nil in nil nil) (return))))))))))
      (with-open-file (f {out} :direction :output :if-exists :supersede)
        (write-string out f))
      (excl:exit 0 :no-unwind t :quiet t))
  (error () (excl:exit 2 :no-unwind t :quiet t)))
"""

    def __init__(self, sneps_dir, timeout=300):
        self.sneps_dir = Path(sneps_dir).resolve()
        self.exe = self.sneps_dir / "Sneps-2.7.exe"
        self.config = self.sneps_dir / "sneps_config.lisp"
        self.timeout = timeout
        if not self.exe.is_file():
            raise FileNotFoundError(f"SNePS executable not found: {self.exe}")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def run(self, statements, query):
        good, errors = _split_checked(statements)
        lines = transcript(good, query) + ["lisp"]  # "lisp" leaves the REPL so the driver can exit
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "transcript.txt"
            driver = Path(tmp) / "driver.lisp"
            # Allegro reads the driver in the Windows ANSI code page, which the temp path must survive.
            driver.write_text(self._DRIVER.format(
                text=lisp_string("\n".join(lines) + "\n"), secs=self.timeout,
                out=lisp_string(out.as_posix())), encoding="mbcs" if os.name == "nt" else "latin-1")
            try:
                proc = subprocess.run([str(self.exe), "+B", "+cn", "-L", str(driver), "--",
                                       "-config-file", str(self.config)],
                                      cwd=self.sneps_dir, timeout=self.timeout + 60, check=False)
            except subprocess.TimeoutExpired:
                return [], errors + [(None, f"SNePS did not exit within {self.timeout + 60} s and was killed")]
            if not out.is_file():
                return [], errors + [(None, f"SNePS wrote no transcript (exit code {proc.returncode})")]
            output = out.read_text(encoding="utf-8", errors="replace").splitlines()
        return output, errors + [(None, m) for m in _driver_markers(output)]


def _driver_markers(lines):
    """Error and timeout reports in a transcript, one message per report."""
    messages, current = [], None
    for line in lines:
        if current is not None:
            current.append(line.strip())
            if line.rstrip().endswith(">>"):
                messages.append(" ".join(current))
                current = None
        elif line.startswith("<<LISP ERROR:"):
            if line.rstrip().endswith(">>"):
                messages.append(line.strip())
            else:
                current = [line.strip()]
        elif "<<TIMEOUT>>" in line or "Eof Unexpected" in line:
            messages.append(line.strip())
    if current is not None:
        messages.append(" ".join(current))
    return messages


def transcript(statements, query):
    """The SNePSLOG input lines for one scene: start from an empty KB, assert, then ask."""
    return ["clearkb"] + [s + "." for s in statements] + [f"ask({query})."]


def lisp_string(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
