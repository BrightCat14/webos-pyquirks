#!/usr/bin/env python
"""Audit webOS TV Python 2.7 stdlib gaps + webos-pyquirks shims.

Works on both the TV (Python 2.7) and a dev machine (Python 2/3).

Usage:
    python audit_tv_python.py [--stdlib PATH] [--modules PATH] [-v]

    --stdlib PATH   path to dumped TV stdlib, e.g.
                    ../usr/lib/python2.7  (static/offline check only)
    --modules PATH  path to webos-pyquirks/modules (default: ./modules
                    relative to this script)
    -v              verbose per-test detail

Exit code: 0 if all quirk functional tests pass, 1 otherwise.
Static/live stdlib gap report never fails the exit code on its own;
it is informational (TV is *supposed* to be stripped).
"""
from __future__ import print_function

import os
import sys
import traceback

# ---------------------------------------------------------------------------
# curated module lists
# ---------------------------------------------------------------------------

# Modules this repo claims to quirk/polyfill.
QUIRK_MODULES = ["fcntl", "subprocess", "simplejson", "json"]

# Broader stdlib probes to discover "what's next to break".
# (name, kind) where kind in builtin/extension/pure/package.
BROAD_PROBES = [
    # quirks (expected MISSING on stock TV, PROVIDED by this repo)
    ("fcntl", "quirk"), ("subprocess", "quirk"), ("json", "quirk"),
    ("simplejson", "quirk"),
    # threading stack (almost certainly the next ImportError you hit)
    ("thread", "builtin"), ("threading", "pure"), ("dummy_thread", "pure"),
    ("dummy_threading", "pure"), ("Queue", "pure"),
    ("multiprocessing", "package"),
    # commonly imported helpers
    ("argparse", "pure"), ("contextlib", "pure"), ("unittest", "package"),
    ("xml", "package"), ("email", "package"), ("logging", "package"),
    ("ctypes", "package"), ("ssl", "pure"), ("hashlib", "pure"),
    ("sqlite3", "package"), ("gzip", "pure"), ("bz2", "pure"),
    ("zipfile", "pure"), ("tarfile", "pure"), ("zlib", "extension"),
    ("mmap", "extension"), ("select", "extension"), ("signal", "builtin"),
    ("errno", "builtin"), ("imp", "builtin"), ("optparse", "pure"),
    ("getpass", "pure"), ("BaseHTTPServer", "pure"),
    ("SocketServer", "pure"), ("SimpleHTTPServer", "pure"),
    ("imaplib", "pure"), ("socket", "pure"), ("datetime", "extension"),
    ("decimal", "pure"), ("numbers", "pure"), ("itertools", "extension"),
    ("collections", "pure"), ("struct", "pure"), ("codecs", "pure"),
    ("io", "pure"), ("os", "pure"), ("tempfile", "pure"),
    ("shutil", "pure"), ("pickle", "pure"), ("traceback", "pure"),
    ("weakref", "pure"), ("time", "extension"),
]

# Builtins are assumed present even with no file on disk.
BUILTINS = set(["sys", "__builtin__", "exceptions", "gc", "marshal",
                "posix", "signal", "thread", "errno", "imp"])


def parse_argv(argv):
    stdlib = None
    modules = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "modules")
    verbose = False
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--stdlib" and i + 1 < len(argv):
            stdlib = argv[i + 1]
            i += 2
        elif a == "--modules" and i + 1 < len(argv):
            modules = argv[i + 1]
            i += 2
        elif a in ("-v", "--verbose"):
            verbose = True
            i += 1
        elif a in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        else:
            print("unknown arg: %s" % a)
            print(__doc__)
            sys.exit(2)
    return stdlib, modules, verbose


# ---------------------------------------------------------------------------
# static (offline, against a firmware dump) check
# ---------------------------------------------------------------------------

def static_present(stdlib_root, name):
    """Return True if name looks present in a dumped usr/lib/python2.7 tree."""
    if name in BUILTINS:
        return True  # frozen into the binary, no file expected
    base = os.path.join(stdlib_root, name)
    if os.path.isfile(base + ".py") or os.path.isfile(base + ".pyc"):
        return True
    if os.path.isdir(base) and os.path.isfile(
            os.path.join(base, "__init__.py")):
        return True
    dyn = os.path.join(stdlib_root, "lib-dynload")
    for cand in (name + ".so", "_" + name + ".so",
                 name + ".module.so"):
        if os.path.isfile(os.path.join(dyn, cand)):
            return True
    return False


def run_static_check(stdlib_root):
    missing, present = [], []
    for name, _kind in BROAD_PROBES:
        (present if static_present(stdlib_root, name) else missing).append(name)
    return present, missing


# ---------------------------------------------------------------------------
# live (import on this interpreter) check
# ---------------------------------------------------------------------------

def live_import(name):
    try:
        __import__(name)
        return "OK", ""
    except SyntaxError as e:
        return ("FAIL",
                "SyntaxError (py2-only code on py3?): %s" % e)
    except ImportError as e:
        return "MISSING", str(e)
    except Exception as e:  # e.g. OSError from ctypes on wrong platform
        return ("FAIL", "%s: %s" % (type(e).__name__, e))


def run_live_check(names):
    rows = []
    for n in names:
        status, detail = live_import(n)
        rows.append((n, status, detail))
    return rows


def print_live_rows(rows, verbose):
    for name, status, detail in rows:
        line = "  %-18s %s" % (name, status)
        if verbose and detail:
            line += "  (%s)" % detail
        elif status not in ("OK",):
            line += "  (%s)" % detail[:100]
        print(line)


# ---------------------------------------------------------------------------
# functional tests for the quirks themselves
# ---------------------------------------------------------------------------

results = []  # (name, PASS/FAIL/SKIP, detail)


def report(name, status, detail=""):
    results.append((name, status, detail))


def _which(name):
    for c in ("/bin/" + name, "/usr/bin/" + name):
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


# ---------------- fcntl ----------------

FLOCK_CONSTS = ("LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN",
                "F_DUPFD", "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL",
                "F_GETLK", "F_SETLK", "F_SETLKW", "F_SETOWN", "F_GETOWN",
                "FD_CLOEXEC", "F_RDLCK", "F_WRLCK", "F_UNLCK")

FIONREAD = 0x541B  # Linux, all arches


def test_fcntl(verbose):
    try:
        import fcntl as f
    except Exception as e:
        report("fcntl.import", "SKIP",
               "cannot import fcntl here: %s: %s"
               % (type(e).__name__, e))
        return
    report("fcntl.import", "PASS", getattr(f, "__file__", "?"))
    for const in FLOCK_CONSTS:
        if hasattr(f, const):
            report("fcntl.const.%s" % const, "PASS")
        else:
            report("fcntl.const.%s" % const, "FAIL", "constant missing")
    for fn in ("fcntl", "ioctl", "flock", "lockf"):
        if callable(getattr(f, fn, None)):
            report("fcntl.has.%s" % fn, "PASS")
        else:
            report("fcntl.has.%s" % fn, "FAIL", "function missing")
    # native struct flock size sanity (catches the old "hhqqi" packing bug:
    # 16 = 32-bit ARM/MIPS, 32 = 64-bit with tail pad)
    try:
        import ctypes
        if hasattr(f, "_Flock"):
            size = ctypes.sizeof(f._Flock)
            report("fcntl._Flock.size",
                   "PASS" if size in (16, 32) else "FAIL",
                   "sizeof=%d (expect 16 on 32-bit ARM, 32 on 64-bit)" % size)
        else:
            report("fcntl._Flock.size", "FAIL",
                   "no _Flock struct: old struct.pack code still in use?")
    except Exception as e:
        report("fcntl._Flock.size", "FAIL",
               "%s: %s" % (type(e).__name__, e))

    import tempfile
    tmp = tempfile.TemporaryFile()
    try:
        fd = tmp.fileno()
        # int paths
        try:
            v = f.fcntl(fd, f.F_GETFD)
            report("fcntl.fcntl(F_GETFD)", "PASS", "flags=%r" % (v,))
        except Exception as e:
            report("fcntl.fcntl(F_GETFD)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
        try:
            v = f.fcntl(fd, f.F_GETFL)
            report("fcntl.fcntl(F_GETFL)", "PASS" if v >= 0 else "FAIL",
                   "flags=%r" % (v,))
        except Exception as e:
            report("fcntl.fcntl(F_GETFL)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
        # F_SETFD roundtrip (set + restore, so we leave no side effects)
        try:
            old = f.fcntl(fd, f.F_GETFD)
            f.fcntl(fd, f.F_SETFD, old | f.FD_CLOEXEC)
            new = f.fcntl(fd, f.F_GETFD)
            ok = bool(new & f.FD_CLOEXEC)
            f.fcntl(fd, f.F_SETFD, old)
            report("fcntl.fcntl(F_SETFD,CLOEXEC)",
                   "PASS" if ok else "FAIL", "old=%r new=%r" % (old, new))
        except Exception as e:
            report("fcntl.fcntl(F_SETFD,CLOEXEC)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
        # file object (not just int fd) must be accepted
        try:
            f.fcntl(tmp, f.F_GETFD)
            report("fcntl.fcntl(fileobj)", "PASS")
        except Exception as e:
            report("fcntl.fcntl(fileobj)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
        # bytes/str struct-arg path via F_GETLK (32 zero bytes in)
        try:
            out = f.fcntl(fd, f.F_GETLK, b"\x00" * 32)
            report("fcntl.fcntl(F_GETLK,bytes)",
                   "PASS" if isinstance(out, bytes) and len(out) == 32
                   else "FAIL", "len=%r" % (len(out) if out else None,))
        except Exception as e:
            report("fcntl.fcntl(F_GETLK,bytes)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
        try:
            out = f.fcntl(fd, f.F_GETLK, "\x00" * 32)
            report("fcntl.fcntl(F_GETLK,str)", "PASS")
        except Exception as e:
            report("fcntl.fcntl(F_GETLK,str)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
        # error paths
        try:
            f.fcntl(fd, f.F_GETFD, [1])
            report("fcntl.fcntl(badtype)", "FAIL", "no TypeError raised")
        except TypeError:
            report("fcntl.fcntl(badtype)", "PASS", "TypeError as expected")
        except Exception as e:
            report("fcntl.fcntl(badtype)", "FAIL",
                   "wrong exc: %s: %s" % (type(e).__name__, e))
        try:
            f.fcntl(-1, f.F_GETFD)
            report("fcntl.fcntl(badfd)", "FAIL", "no OSError raised")
        except OSError:
            report("fcntl.fcntl(badfd)", "PASS", "OSError as expected")
        except Exception as e:
            report("fcntl.fcntl(badfd)", "FAIL",
                   "wrong exc: %s: %s" % (type(e).__name__, e))
        # flock variants
        for op_name, op in (("SH", f.LOCK_SH), ("EX", f.LOCK_EX),
                            ("SH_NB", f.LOCK_SH | f.LOCK_NB),
                            ("EX_NB", f.LOCK_EX | f.LOCK_NB)):
            try:
                f.flock(fd, op)
                f.flock(fd, f.LOCK_UN)
                report("fcntl.flock(%s/UN)" % op_name, "PASS")
            except Exception as e:
                report("fcntl.flock(%s/UN)" % op_name, "FAIL",
                       "%s: %s" % (type(e).__name__, e))
        try:
            f.flock(tmp, f.LOCK_EX | f.LOCK_NB)
            f.flock(tmp, f.LOCK_UN)
            report("fcntl.flock(fileobj)", "PASS")
        except Exception as e:
            report("fcntl.flock(fileobj)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
        # lockf variants (incl. non-zero start/len: exercises native packing)
        for op_name, op, ln, st in (("SH", f.LOCK_SH, 0, 0),
                                    ("EX", f.LOCK_EX, 0, 0),
                                    ("SH_NB", f.LOCK_SH | f.LOCK_NB, 0, 0),
                                    ("EX_NB", f.LOCK_EX | f.LOCK_NB, 0, 0),
                                    ("EX_range", f.LOCK_EX | f.LOCK_NB, 5, 10)):
            try:
                f.lockf(fd, op, ln, st, 0)
                f.lockf(fd, f.LOCK_UN, ln, st, 0)
                report("fcntl.lockf(%s)" % op_name, "PASS")
            except Exception as e:
                report("fcntl.lockf(%s)" % op_name, "FAIL",
                       "%s: %s" % (type(e).__name__, e))
        try:
            f.lockf(fd, 0)
            report("fcntl.lockf(badcmd)", "FAIL", "no ValueError raised")
        except ValueError:
            report("fcntl.lockf(badcmd)", "PASS", "ValueError as expected")
        except Exception as e:
            report("fcntl.lockf(badcmd)", "FAIL",
                   "wrong exc: %s: %s" % (type(e).__name__, e))
        # ioctl on a pipe with real data (FIONREAD needs a live pipe,
        # NOT a regular file: NULL/regular-file use faults with EFAULT,
        # exactly like CPython)
        r = w = None
        try:
            import struct
            r, w = os.pipe()
            os.write(w, b"abcd")
            # bytearray mutate path (regression: used ctypes.from_buffer
            # + byref, i.e. AttributeError + pointer-to-pointer EFAULT)
            try:
                buf = bytearray(b"\x00" * 4)
                f.ioctl(r, FIONREAD, buf)
                n = struct.unpack("i", bytes(buf))[0]
                report("fcntl.ioctl(bytearray,FIONREAD)",
                       "PASS" if n == 4 else "FAIL",
                       "available=%r" % (n,))
            except Exception as e:
                report("fcntl.ioctl(bytearray,FIONREAD)", "FAIL",
                       "%s: %s" % (type(e).__name__, e))
            # bytes return path
            try:
                out = f.ioctl(r, FIONREAD, b"\x00" * 4)
                n = struct.unpack("i", bytes(out))[0]
                report("fcntl.ioctl(bytes,FIONREAD)",
                       "PASS" if n == 4 else "FAIL",
                       "available=%r" % (n,))
            except Exception as e:
                report("fcntl.ioctl(bytes,FIONREAD)", "FAIL",
                       "%s: %s" % (type(e).__name__, e))
            # str path
            try:
                f.ioctl(r, FIONREAD, "\x00" * 4)
                report("fcntl.ioctl(str,FIONREAD)", "PASS")
            except Exception as e:
                report("fcntl.ioctl(str,FIONREAD)", "FAIL",
                       "%s: %s" % (type(e).__name__, e))
            # int/NULL path: kernel must answer EFAULT, same as CPython
            try:
                f.ioctl(r, FIONREAD, 0)
                report("fcntl.ioctl(int0,FIONREAD)", "FAIL",
                       "expected EFAULT, got success")
            except OSError as e:
                import errno
                report("fcntl.ioctl(int0,FIONREAD)",
                       "PASS" if e.errno == errno.EFAULT else "FAIL",
                       "errno=%s (EFAULT=parity with CPython)" % e.errno)
            except Exception as e:
                report("fcntl.ioctl(int0,FIONREAD)", "FAIL",
                       "%s: %s" % (type(e).__name__, e))
            # bad-type path
            try:
                f.ioctl(r, FIONREAD, [1])
                report("fcntl.ioctl(badtype)", "FAIL", "no TypeError raised")
            except TypeError:
                report("fcntl.ioctl(badtype)", "PASS",
                       "TypeError as expected")
            except Exception as e:
                report("fcntl.ioctl(badtype)", "FAIL",
                       "wrong exc: %s: %s" % (type(e).__name__, e))
        except Exception as e:
            report("fcntl.ioctl(pipe-setup)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
            if verbose:
                traceback.print_exc()
        finally:
            for _fd in (r, w):
                if _fd is not None:
                    try:
                        os.close(_fd)
                    except Exception:
                        pass
    finally:
        tmp.close()


# ---------------- subprocess ----------------

def test_subprocess(verbose):
    try:
        import subprocess as sp
    except SyntaxError as e:
        if sys.version_info[0] >= 3:
            report("subprocess.import", "SKIP",
                   "py2-only quirk, run functional tests on TV: %s" % e)
            return
        report("subprocess.import", "FAIL",
               "py2-only syntax, unimportable on py3: %s" % e)
        return
    except Exception as e:
        report("subprocess.import", "SKIP",
               "cannot import here: %s: %s"
               % (type(e).__name__, e))
        return
    report("subprocess.import", "PASS", getattr(sp, "__file__", "?"))
    for fn in ("Popen", "call", "check_call", "check_output",
               "PIPE", "STDOUT", "CalledProcessError", "list2cmdline"):
        if hasattr(sp, fn):
            report("subprocess.has.%s" % fn, "PASS")
        else:
            report("subprocess.has.%s" % fn, "FAIL", "missing attr")
    for m in ("communicate", "poll", "wait", "send_signal",
              "terminate", "kill"):
        if hasattr(sp.Popen, m):
            report("subprocess.Popen.%s" % m, "PASS")
        else:
            report("subprocess.Popen.%s" % m, "FAIL", "missing method")
    # list2cmdline quoting
    try:
        q = sp.list2cmdline(["a b", "c"])
        report("subprocess.list2cmdline",
               "PASS" if q == '"a b" c' else "FAIL", "got=%r" % (q,))
    except Exception as e:
        report("subprocess.list2cmdline", "FAIL",
               "%s: %s" % (type(e).__name__, e))

    echo = _which("echo")
    if echo is None:
        report("subprocess.call", "SKIP", "no /bin/echo on this box")
        return
    # call ok
    try:
        rc = sp.call([echo, "quirks-probe"])
        report("subprocess.call",
               "PASS" if rc == 0 else "FAIL", "rc=%r" % (rc,))
    except Exception as e:
        report("subprocess.call", "FAIL",
               "%s: %s" % (type(e).__name__, e))
        if verbose:
            traceback.print_exc()
    # call failing (no exception, nonzero rc)
    false = _which("false")
    fail_cmd = [false] if false else ["/bin/ls", "/nonexistent-quirks-probe"]
    try:
        rc = sp.call(fail_cmd)
        report("subprocess.call(fail)",
               "PASS" if rc != 0 else "FAIL", "rc=%r" % (rc,))
    except Exception as e:
        report("subprocess.call(fail)", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    # check_call ok + failing
    try:
        rc = sp.check_call([echo, "hi"])
        report("subprocess.check_call",
               "PASS" if rc == 0 else "FAIL", "rc=%r" % (rc,))
    except Exception as e:
        report("subprocess.check_call", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    try:
        sp.check_call(fail_cmd)
        report("subprocess.check_call(fail)", "FAIL", "no exception raised")
    except sp.CalledProcessError as e:
        report("subprocess.check_call(fail)",
               "PASS" if e.returncode != 0 and e.cmd == fail_cmd else "FAIL",
               "rc=%r cmd=%r" % (e.returncode, e.cmd))
    except Exception as e:
        report("subprocess.check_call(fail)", "FAIL",
               "wrong exc: %s: %s" % (type(e).__name__, e))
    # check_output ok + failing (output attr)
    try:
        out = sp.check_output([echo, "hello"])
        report("subprocess.check_output",
               "PASS" if b"hello" in out else "FAIL", "out=%r" % (out,))
    except Exception as e:
        report("subprocess.check_output", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    try:
        sp.check_output(fail_cmd)
        report("subprocess.check_output(fail)", "FAIL",
               "no exception raised")
    except sp.CalledProcessError as e:
        report("subprocess.check_output(fail)",
               "PASS" if e.returncode != 0 and hasattr(e, "output") else "FAIL",
               "rc=%r" % (e.returncode,))
    except Exception as e:
        report("subprocess.check_output(fail)", "FAIL",
               "wrong exc: %s: %s" % (type(e).__name__, e))
    # Popen attrs + poll/wait
    try:
        p = sp.Popen([echo, "hi"], stdout=sp.PIPE, stderr=sp.PIPE)
        report("subprocess.Popen.pid",
               "PASS" if isinstance(p.pid, int) and p.pid > 0 else "FAIL",
               "pid=%r" % (p.pid,))
        out, err = p.communicate()
        report("subprocess.Popen.communicate",
               "PASS" if p.returncode == 0 and b"hi" in out else "FAIL",
               "rc=%r out=%r" % (p.returncode, out))
        report("subprocess.Popen.poll",
               "PASS" if p.poll() == 0 else "FAIL",
               "poll=%r" % (p.poll(),))
        report("subprocess.Popen.streams",
               "PASS" if p.stdout is not None and p.stderr is not None
               and p.stdin is None else "FAIL",
               "stdin/stdout/stderr wiring")
    except Exception as e:
        report("subprocess.Popen.communicate", "FAIL",
               "%s: %s" % (type(e).__name__, e))
        if verbose:
            traceback.print_exc()
    # communicate(input) through cat
    cat = _which("cat")
    if cat is None:
        report("subprocess.communicate(input)", "SKIP", "no cat on this box")
    else:
        try:
            p = sp.Popen([cat], stdin=sp.PIPE, stdout=sp.PIPE,
                         stderr=sp.PIPE)
            out, err = p.communicate(b"ping")
            report("subprocess.communicate(input)",
                   "PASS" if out == b"ping" and p.returncode == 0 else "FAIL",
                   "out=%r rc=%r" % (out, p.returncode))
        except Exception as e:
            report("subprocess.communicate(input)", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
            if verbose:
                traceback.print_exc()
    # stderr=STDOUT merge
    ls = _which("ls")
    if ls is None:
        report("subprocess.stderr=STDOUT", "SKIP", "no ls on this box")
    else:
        try:
            p = sp.Popen([ls, "/nonexistent-quirks-probe"],
                         stdout=sp.PIPE, stderr=sp.STDOUT)
            out, err = p.communicate()
            report("subprocess.stderr=STDOUT",
                   "PASS" if err is None and out else "FAIL",
                   "err=%r out=%r" % (err, out))
        except Exception as e:
            report("subprocess.stderr=STDOUT", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
    # shell=True (goes through /bin/sh on posix)
    try:
        out = sp.check_output("echo shellprobe", shell=True)
        report("subprocess.shell=True",
               "PASS" if b"shellprobe" in out else "FAIL",
               "out=%r" % (out,))
    except Exception as e:
        report("subprocess.shell=True", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    # terminate a live child (reaps via wait, no zombie left)
    sleep = _which("sleep")
    if sleep is None:
        report("subprocess.terminate", "SKIP", "no sleep on this box")
    else:
        import signal
        p = None
        try:
            p = sp.Popen([sleep, "30"])
            p.terminate()
            rc = p.wait()
            report("subprocess.terminate",
                   "PASS" if rc == -signal.SIGTERM else "FAIL",
                   "rc=%r (expect %r)" % (rc, -signal.SIGTERM))
        except Exception as e:
            report("subprocess.terminate", "FAIL",
                   "%s: %s" % (type(e).__name__, e))
            if verbose:
                traceback.print_exc()
        finally:
            if p is not None and p.returncode is None:
                try:
                    p.kill()
                    p.wait()
                except Exception:
                    pass


# ---------------- simplejson / json ----------------

def test_json_simplejson(verbose):
    try:
        import simplejson as sj
    except Exception as e:
        report("simplejson.import", "FAIL",
               "%s: %s" % (type(e).__name__, e))
        if verbose:
            traceback.print_exc()
        return
    if not hasattr(sj, "dumps") or not hasattr(sj, "loads"):
        report("simplejson.import", "FAIL",
               "module has no dumps/loads (file=%s): nested "
               "simplejson/simplejson layout, flatten the package"
               % getattr(sj, "__file__", "?"))
        return
    report("simplejson.import", "PASS", getattr(sj, "__file__", "?"))
    for fn in ("dumps", "loads", "dump", "load",
               "JSONDecoder", "JSONEncoder", "JSONDecodeError"):
        if hasattr(sj, fn):
            report("simplejson.has.%s" % fn, "PASS")
        else:
            report("simplejson.has.%s" % fn, "FAIL", "missing attr")
    # core roundtrips
    try:
        obj = {"hello": u"w\u00f6rld", "n": 42, "l": [1, 2.5, None, True]}
        s = sj.dumps(obj, ensure_ascii=False)
        back = sj.loads(s)
        report("simplejson.roundtrip",
               "PASS" if back == obj else "FAIL", "s=%r" % (s,))
    except Exception as e:
        report("simplejson.roundtrip", "FAIL",
               "%s: %s" % (type(e).__name__, e))
        if verbose:
            traceback.print_exc()
    try:
        s = sj.dumps({u"\xe9": 1}, ensure_ascii=True)
        back = sj.loads(s)
        report("simplejson.ascii",
               "PASS" if back == {u"\xe9": 1} and "\\u" in s else "FAIL",
               "s=%r" % (s,))
    except Exception as e:
        report("simplejson.ascii", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    # dump/load via file object
    try:
        import tempfile
        obj = {"a": [1, 2, {"b": None}], "u": u"\u1234"}
        tmpf = tempfile.TemporaryFile(mode="w+")
        try:
            sj.dump(obj, tmpf)
            tmpf.seek(0)
            back = sj.load(tmpf)
            report("simplejson.dump/load",
                   "PASS" if back == obj else "FAIL", "")
        finally:
            tmpf.close()
    except Exception as e:
        report("simplejson.dump/load", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    # deterministic output
    try:
        s = sj.dumps({"b": 1, "a": 2}, sort_keys=True, indent=2)
        report("simplejson.sort_keys+indent",
               "PASS" if s.find('"a"') < s.find('"b"') else "FAIL",
               "s=%r" % (s,))
    except Exception as e:
        report("simplejson.sort_keys+indent", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    try:
        s = sj.dumps([1, 2, {"a": 3}], separators=(",", ":"))
        report("simplejson.separators",
               "PASS" if s == '[1,2,{"a":3}]' else "FAIL", "s=%r" % (s,))
    except Exception as e:
        report("simplejson.separators", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    # hooks / options
    try:
        from decimal import Decimal
        v = sj.loads("1.1", parse_float=Decimal)
        report("simplejson.parse_float",
               "PASS" if v == Decimal("1.1") else "FAIL", "v=%r" % (v,))
    except Exception as e:
        report("simplejson.parse_float", "FAIL",
               "%s: %s" % (type(e).__name__, e))

    def _as_complex(dct):
        if "__complex__" in dct:
            return complex(dct["real"], dct["imag"])
        return dct

    try:
        v = sj.loads('{"__complex__": true, "real": 1, "imag": 2}',
                     object_hook=_as_complex)
        report("simplejson.object_hook",
               "PASS" if v == (1 + 2j) else "FAIL", "v=%r" % (v,))
    except Exception as e:
        report("simplejson.object_hook", "FAIL",
               "%s: %s" % (type(e).__name__, e))

    def _default(o):
        if isinstance(o, set):
            return sorted(o)
        raise TypeError(repr(o) + " is not JSON serializable")

    try:
        s = sj.dumps(set([2, 1]), default=_default)
        back = sj.loads(s)
        report("simplejson.default",
               "PASS" if back == [1, 2] else "FAIL", "s=%r" % (s,))
    except Exception as e:
        report("simplejson.default", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    # bigint + nesting
    try:
        big = 2 ** 100
        deep = {"x": [[[{"y": big}]]]}
        report("simplejson.bigint+nested",
               "PASS" if sj.loads(sj.dumps(deep)) == deep else "FAIL", "")
    except Exception as e:
        report("simplejson.bigint+nested", "FAIL",
               "%s: %s" % (type(e).__name__, e))
    # error surface
    try:
        sj.loads("{not json")
        report("simplejson.loads(bad)", "FAIL", "no exception raised")
    except ValueError:
        report("simplejson.loads(bad)", "PASS", "ValueError as expected")
    except Exception as e:
        report("simplejson.loads(bad)", "FAIL",
               "wrong exc: %s: %s" % (type(e).__name__, e))
    try:
        sj.dumps(set([1]))
        report("simplejson.dumps(set)", "FAIL", "no exception raised")
    except TypeError:
        report("simplejson.dumps(set)", "PASS", "TypeError as expected")
    except Exception as e:
        report("simplejson.dumps(set)", "FAIL",
               "wrong exc: %s: %s" % (type(e).__name__, e))
    # stock-json parity (on dev: real stdlib; on TV: our json shim)
    try:
        import json as j
        if getattr(j, "__file__", None) == getattr(sj, "__file__", None):
            report("json.parity", "SKIP",
                   "json IS simplejson here (alias shim), nothing to compare")
        else:
            fix = {"b": 1, "a": [1, u"x", None]}
            a = j.dumps(fix, sort_keys=True)
            b = sj.dumps(fix, sort_keys=True)
            report("json.parity",
                   "PASS" if a == b and j.loads(a) == sj.loads(b) else "FAIL",
                   "stdlib=%r quirk=%r" % (a, b))
    except Exception as e:
        report("json.parity", "SKIP",
               "no json module here: %s: %s" % (type(e).__name__, e))
    # _speedups C ext must degrade gracefully (TV has no compiler)
    try:
        import simplejson._speedups  # noqa
        report("simplejson._speedups", "PASS", "C ext present")
    except Exception as e:
        report("simplejson._speedups", "SKIP",
               "pure-python fallback (%s)" % type(e).__name__)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv):
    stdlib, modules, verbose = parse_argv(argv)

    print("== webos-pyquirks audit ==")
    print("python: %s" % sys.version.replace("\n", " "))
    print("platform: %s" % sys.platform)

    # 1. static dump check
    if stdlib:
        stdlib = os.path.abspath(stdlib)
        print("\n-- static check vs dump: %s --" % stdlib)
        if not os.path.isdir(stdlib):
            print("no such directory, skipping static check")
        else:
            present, missing = run_static_check(stdlib)
            print("present on TV (%d): %s"
                  % (len(present), ", ".join(sorted(present))))
            print("MISSING on TV (%d): %s"
                  % (len(missing), ", ".join(sorted(missing))))
            for q in QUIRK_MODULES:
                if q in missing:
                    print("  quirk %-10s : MISSING (provided by quirks)" % q)
                elif q in present:
                    print("  quirk %-10s : present (already on TV?!)" % q)

    # 2. live import check WITHOUT quirks (pure TV baseline on TV,
    #    host stdlib on dev; quirks must not shadow this pass)
    print("\n-- live import check (this interpreter, no quirks on path) --")
    print_live_rows(run_live_check([n for n, _k in BROAD_PROBES]), verbose)

    # 3. put quirks on path (same as bootstrap.py) and re-check:
    #    this is the pass that proves the quirks close the gaps.
    print("\n-- live import check (WITH quirks on path) --")
    modules = os.path.abspath(modules)
    if os.path.isdir(modules):
        if modules not in sys.path:
            sys.path.insert(0, modules)
        print("modules dir: %s" % modules)
        for n in QUIRK_MODULES:
            sys.modules.pop(n, None)  # force re-import through quirks
        print_live_rows(run_live_check([n for n, _k in BROAD_PROBES]),
                        verbose)
    else:
        print("modules dir NOT FOUND: %s" % modules)

    # 4. functional quirk tests (every public function, not just imports)
    print("\n-- functional quirk tests --")
    test_fcntl(verbose)
    test_subprocess(verbose)
    test_json_simplejson(verbose)

    npass = sum(1 for _n, s, _d in results if s == "PASS")
    nfail = sum(1 for _n, s, _d in results if s == "FAIL")
    nskip = sum(1 for _n, s, _d in results if s == "SKIP")
    for name, status, detail in results:
        if verbose or status == "FAIL":
            print("  [%s] %-36s %s" % (status, name, detail))
        elif status == "SKIP":
            print("  [SKIP] %-36s %s" % (name, detail[:90]))
    print("\nfunctional: %d PASS, %d FAIL, %d SKIP" % (npass, nfail, nskip))
    if nfail:
        print("RESULT: FAIL (see [FAIL] rows above)")
        return 1
    print("RESULT: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
