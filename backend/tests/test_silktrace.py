import hashlib
from pathlib import Path
from app.silktrace.service import SILKTRACE


def test_unknown_file_is_preserved_and_hashed(tmp_path: Path):
    src=tmp_path/"mystery.blackbox"
    src.write_bytes(bytes(range(256))*8)
    svc=SILKTRACE(tmp_path/"silktrace")
    rec=svc.ingest(src.name,src,"tester")
    assert rec["support_level"] in {"L1","L2"}
    assert rec["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    assert rec["sha256_verified_after_copy"] is True
    checked=svc.get(rec["evidence_id"])
    assert checked["integrity"]["status"] == "VALID"


def test_csv_extracts_columns(tmp_path: Path):
    src=tmp_path/"flight.csv"
    src.write_text("timestamp,roll,pitch\n0,1.0,2.0\n1,1.1,2.1\n",encoding="utf-8")
    rec=SILKTRACE(tmp_path/"store").ingest(src.name,src,"tester")
    assert rec["format_id"] == "delimited.telemetry"
    assert {c["name"] for c in rec["inspection"]["channels"]} == {"timestamp","roll","pitch"}


def test_tampering_is_detected(tmp_path: Path):
    src=tmp_path/"x.bin"; src.write_bytes(b"unknown-data-"*100)
    svc=SILKTRACE(tmp_path/"store"); rec=svc.ingest(src.name,src,"tester")
    stored=svc.evidence/rec["evidence_id"]/rec["stored_filename"]
    stored.chmod(0o640); stored.write_bytes(b"tampered")
    assert svc.get(rec["evidence_id"])["integrity"]["status"] == "MODIFIED"


def test_custom_schema_decodes_without_touching_original(tmp_path: Path):
    import struct
    src=tmp_path/"custom.dat"
    src.write_bytes(struct.pack("<If",100,1.25)+struct.pack("<If",200,2.5))
    svc=SILKTRACE(tmp_path/"store"); rec=svc.ingest(src.name,src,"tester")
    result=svc.apply_schema(rec["evidence_id"],{"record_size":8,"endianness":"little","fields":[{"name":"time_ms","offset":0,"type":"u32","unit":"ms"},{"name":"signal","offset":4,"type":"f32"}]},"tester")
    assert result["record_count_decoded"] == 2
    assert result["samples"][1]["signal"] == 2.5
    assert svc.get(rec["evidence_id"])["integrity"]["status"] == "VALID"
