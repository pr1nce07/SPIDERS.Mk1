"""Builds and runs the portable C++ GNSSIntegrity unit tests (firmware/native/tests).

Skipped when no C++ compiler is found. Set CXX to choose one (for example MSYS2's
ucrt64 g++ on Windows: CXX=C:/msys64/ucrt64/bin/g++.exe).
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "firmware" / "native"


def _compiler():
    cxx = os.environ.get("CXX")
    if cxx:
        return shutil.which(cxx) or (cxx if Path(cxx).is_file() else None)
    for name in ("g++", "clang++"):
        found = shutil.which(name)
        if found:
            return found
    return None


@pytest.mark.skipif(_compiler() is None, reason="no C++ compiler found (set CXX)")
def test_native_gnss_integrity_engine(tmp_path):
    cxx = _compiler()
    src = NATIVE / "AP_IDS" / "GNSSIntegrity"
    strict = ["-std=gnu++11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wshadow", "-Wdouble-promotion",
              "-Wfloat-conversion", "-fno-exceptions", "-fno-rtti"]
    env = dict(os.environ)
    env["PATH"] = str(Path(cxx).parent) + os.pathsep + env.get("PATH", "")   # runtime DLLs live next to the compiler

    def run(cmd):
        p = subprocess.run(cmd, capture_output=True, text=True, env=env)
        assert p.returncode == 0, " ".join(cmd) + "\n" + p.stdout[-3000:] + p.stderr[-3000:]

    objs = []
    for f in sorted(src.glob("*.cpp")):
        o = tmp_path / f"{f.stem}.o"
        run([cxx, *strict, "-fsingle-precision-constant", "-I", str(src), "-c", str(f), "-o", str(o)])
        objs.append(str(o))
    t = tmp_path / "test.o"
    run([cxx, "-std=gnu++11", "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(src), "-c",
         str(NATIVE / "tests" / "test_gnss_integrity.cpp"), "-o", str(t)])
    exe = tmp_path / "test_gnss_integrity"
    run([cxx, str(t), *objs, "-o", str(exe)])
    p = subprocess.run([str(exe)], capture_output=True, text=True, env=env, timeout=900)
    assert p.returncode == 0, p.stdout[-4000:] + p.stderr[-2000:]
    assert " 0 failures" in p.stdout
