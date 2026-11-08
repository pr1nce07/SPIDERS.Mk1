"""MAVLink dialect registry — the backend is the single source of truth for
message IDs, names, fields, types, units, enums and extension fields.

Default dialect is the stock `ardupilotmega` shipped with pymavlink, which is what
the supplied Pixhawk6C firmware build compiled against (no PUSHPAK custom
messages were found in the build's generated headers). A verified custom XML can
be loaded with `mavlink.dialect_xml`; it is compiled with pymavlink's mavgen.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

import pymavlink

NUMERIC_TYPES = {"int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t",
                 "uint64_t", "float", "double", "uint8_t_mavlink_version"}


class DialectRegistry:
    def __init__(self, dialect: str = "ardupilotmega", dialect_xml: Optional[str] = None,
                 work_dir: Optional[Path] = None):
        self.dialect_name = dialect
        self.custom_xml = dialect_xml
        self.module = None
        self.load_error: Optional[str] = None
        if dialect_xml:
            try:
                self.module = self._compile_custom(Path(dialect_xml), work_dir or Path("."))
                self.dialect_name = Path(dialect_xml).stem
            except Exception as exc:  # missing/invalid custom dialect must not stop the app
                self.load_error = f"custom dialect failed to load: {exc}"
        if self.module is None:
            self.module = importlib.import_module(f"pymavlink.dialects.v20.{dialect}")
        self.xml_path = self._xml_path()
        self.extensions = self._parse_extensions()
        self.by_id: dict[int, Any] = dict(self.module.mavlink_map)
        self.by_name: dict[str, Any] = {cls.msgname: cls for cls in self.by_id.values()}
        self.enums = self.module.enums

    # ------------------------------------------------------------------ loading
    def _compile_custom(self, xml: Path, work_dir: Path):
        from pymavlink.generator import mavgen
        if not xml.exists():
            raise FileNotFoundError(str(xml))
        digest = hashlib.sha256(xml.read_bytes()).hexdigest()[:12]
        out_dir = work_dir / "dialects"
        out_dir.mkdir(parents=True, exist_ok=True)
        mod_name = f"custom_{xml.stem}_{digest}"
        out_py = out_dir / f"{mod_name}.py"
        if not out_py.exists():
            opts = mavgen.Opts(str(out_py), wire_protocol="2.0", language="Python3", validate=True)
            mavgen.mavgen(opts, [str(xml)])
        spec = importlib.util.spec_from_file_location(mod_name, out_py)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
        self._custom_xml_file = xml
        return mod

    def _xml_path(self) -> Optional[Path]:
        if getattr(self, "_custom_xml_file", None):
            return self._custom_xml_file
        p = Path(pymavlink.__file__).parent / "dialects" / "v20" / f"{self.dialect_name}.xml"
        return p if p.exists() else None

    def _parse_extensions(self) -> dict[str, list[str]]:
        """Extension fields per message, parsed from the XML (+ includes)."""
        out: dict[str, list[str]] = {}
        if not self.xml_path:
            return out
        seen: set[Path] = set()

        def walk(path: Path):
            if path in seen or not path.exists():
                return
            seen.add(path)
            try:
                root = ET.parse(path).getroot()
            except ET.ParseError:
                return
            for inc in root.findall("include"):
                walk(path.parent / (inc.text or "").strip())
            for msg in root.iter("message"):
                ext = False
                names = []
                for child in msg:
                    if child.tag == "extensions":
                        ext = True
                    elif child.tag == "field" and ext:
                        names.append(child.get("name"))
                out[msg.get("name")] = names
        walk(self.xml_path)
        return out

    # ------------------------------------------------------------------ queries
    def message_info(self, cls) -> dict:
        exts = set(self.extensions.get(cls.msgname, []))
        fields = []
        for name, ftype in zip(cls.fieldnames, cls.fieldtypes):
            base = ftype.split("[")[0]
            arr = dict(zip(cls.ordered_fieldnames, cls.array_lengths)).get(name, 0) if isinstance(getattr(cls, "array_lengths", None), list) else 0
            fields.append({
                "name": name, "type": ftype,
                "numeric": base in NUMERIC_TYPES and not arr and base != "char",
                "array_length": arr,
                "units": (getattr(cls, "fieldunits_by_name", None) or {}).get(name),
                "enum": (getattr(cls, "fieldenums_by_name", None) or {}).get(name),
                "extension": name in exts,
            })
        return {"id": cls.id, "name": cls.msgname, "crc_extra": cls.crc_extra, "fields": fields}

    def catalog(self) -> dict:
        msgs = [self.message_info(c) for c in sorted(self.by_id.values(), key=lambda c: c.id)]
        return {"dialect": self.dialect_name, "custom": bool(self.custom_xml and not self.load_error),
                "load_error": self.load_error, "message_count": len(msgs), "messages": msgs}

    def has_message(self, name: str) -> bool:
        return name in self.by_name

    def field_type(self, msg: str, field: str) -> Optional[str]:
        cls = self.by_name.get(msg)
        if not cls or field not in cls.fieldnames:
            return None
        return cls.fieldtypes[cls.fieldnames.index(field)]

    def is_numeric_field(self, msg: str, field: str) -> bool:
        ft = self.field_type(msg, field)
        if ft is None:
            return False
        return ft.split("[")[0] in NUMERIC_TYPES and "[" not in ft

    def msg_id(self, name: str) -> Optional[int]:
        cls = self.by_name.get(name)
        return cls.id if cls else None

    def enum_name(self, enum: str, value: int) -> Optional[str]:
        try:
            return self.enums[enum][int(value)].name
        except Exception:
            return None

    def command_name(self, cmd: int) -> str:
        return self.enum_name("MAV_CMD", cmd) or f"CMD_{cmd}"
