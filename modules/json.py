# json compatibility alias for webOS TV (stdlib json is missing).
#
# Allows plain `import json` to work by re-exporting the vendored
# simplejson package (API-compatible for the common
# dumps/loads/dump/load/JSONDecoder/JSONEncoder surface).
# If a real stdlib json exists elsewhere on sys.path (dev machine),
# it is preferred.
import os as _os
import sys as _sys

_moddir = _os.path.dirname(_os.path.abspath(__file__))
_real = None
try:
    import imp as _imp
    for _entry in list(_sys.path):
        _search = [_entry or _os.getcwd()]
        try:
            _fp, _p, _d = _imp.find_module('json', _search)
        except Exception:
            continue
        # never load ourselves (kills all self-reference paths)
        if _os.path.dirname(_os.path.abspath(_p)) == _moddir:
            try:
                if _fp:
                    _fp.close()
            except Exception:
                pass
            continue
        try:
            _real = _imp.load_module('json', _fp, _p, _d)
        except Exception:
            _real = None
        finally:
            try:
                if _fp:
                    _fp.close()
            except Exception:
                pass
        if _real is not None:
            break
except Exception:
    _real = None

if _real is None:
    from simplejson import *  # noqa
    from simplejson import (  # noqa
        dumps, dump, loads, load,
        JSONDecoder, JSONEncoder,
    )
    try:
        from simplejson import __version__  # noqa
    except ImportError:
        pass
    try:
        from simplejson import JSONDecodeError  # noqa
    except ImportError:
        pass
else:
    # sys.modules['json'] is now the real module; mirror its public API
    # into this namespace for `from json import x` consistency.
    for _n in dir(_real):
        if not _n.startswith('__') or _n in ('__version__', '__all__'):
            try:
                globals()[_n] = getattr(_real, _n)
            except Exception:
                pass
