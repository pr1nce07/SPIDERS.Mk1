import json
from pathlib import Path

from app.silktrace.behavior import analyze
from app.silktrace.dji import inspect_dji
from app.silktrace.knowledge import validate_profile
from app.silktrace.replay import build_replay
from app.silktrace.sandbox import inspect_isolated


def test_recorded_2d_3d_replay_uses_source_values():
    rows=[{"timestamp":i,"latitude":19.0+i/10000,"longitude":72.0+i/10000,"altitude":20+i,
           "roll_deg":i*0.1,"pitch_deg":i*0.2,"yaw_deg":i*0.3} for i in range(25)]
    result=build_replay({"evidence_id":"EV-000000000001","inspection":{"samples":rows,"channels":[]}})
    assert result["has_geospatial"] and result["has_attitude"]
    assert result["points"][5]["lat"] == rows[5]["latitude"]
    assert result["points"][5]["roll_deg"] == rows[5]["roll_deg"]


def test_replay_refuses_to_fabricate_missing_channels():
    result=build_replay({"evidence_id":"EV-000000000001","inspection":{"samples":[{"sample":1}],"channels":[]}})
    assert not result["has_geospatial"] and not result["has_attitude"]
    assert result["coordinate_source"] == "none"


def test_behavior_analysis_is_explicitly_screening_only():
    rows=[{"gyro_x":0.0,"voltage":16.0} for _ in range(20)]
    rows[10]["gyro_x"]=1000.0
    result=analyze(rows)
    assert result["sample_count"] == 20
    assert any(a["channel"]=="gyro_x" for a in result["alerts"])
    assert any("not confirmed" in x.lower() or "hypotheses" in x.lower() for x in result["limitations"])


def test_dji_dat_is_candidate_not_claimed_decoded(tmp_path):
    p=tmp_path/"FLY001.DAT"; p.write_bytes(b"DJI"+bytes(range(256))*10)
    result=inspect_dji(p,p.name)
    assert "candidate" in result["family"].lower()
    assert result["semantic_decode"] is False


def test_custom_vehicle_profile_allows_non_quad_actuator_count():
    p=validate_profile({"name":"Test Hexa","vehicle_type":"multirotor","actuators":[{"channel":i} for i in range(6)]})
    assert len(p["actuators"])==6 and p["verified"] is False


def test_isolated_parser_runs_known_csv(tmp_path):
    p=tmp_path/"unknown.csv"; p.write_text("time,latitude,longitude\n0,19.1,72.8\n1,19.2,72.9\n",encoding="utf-8")
    result=inspect_isolated(p,p.name,timeout=15)
    assert result["format_id"]=="delimited.telemetry"
    assert "subprocess" in result["_isolation"]


def test_betaflight_uses_optional_upstream_decoder(tmp_path, monkeypatch):
    import os
    from app.silktrace.sandbox import inspect_isolated
    bindir=tmp_path/"bin"; bindir.mkdir()
    csv_lines=["time,gyroADC[0],GPS_coord[0],GPS_coord[1],BaroAlt","0,1,191000000,728000000,100","1,2,191001000,728001000,110"]
    if os.name=="nt":
        # Windows can't run shebang scripts; a .cmd wrapper exercises the same PATH lookup and launch.
        tool=bindir/"blackbox_decode.cmd"
        tool.write_text("@echo off\r\n"+"".join(f"echo {line}\r\n" for line in csv_lines),encoding="ascii")
    else:
        tool=bindir/"blackbox_decode"
        tool.write_text("#!/bin/sh\nprintf '"+"\\n".join(csv_lines)+"\\n'\n",encoding="utf-8")
        tool.chmod(0o755)
    monkeypatch.setenv("PATH",str(bindir)+os.pathsep+os.environ.get("PATH",""))
    p=tmp_path/"log.bbl"; p.write_text("H Product:Test\nH Firmware type:Betaflight\nH Field I name:gyroADC\n",encoding="utf-8")
    result=inspect_isolated(p,p.name,timeout=15)
    assert result["format_id"]=="betaflight.blackbox"
    assert result["decoder"]=="Betaflight blackbox_decode"
    assert len(result["samples"])==2


def test_px4_quaternion_and_gps_e7_mapping():
    from app.silktrace.replay import build_replay
    rows=[{"vehicle_gps_position.lat":191000000,"vehicle_gps_position.lon":728000000,
           "vehicle_gps_position.alt":12000,"vehicle_attitude.q[0]":1.0,
           "vehicle_attitude.q[1]":0.0,"vehicle_attitude.q[2]":0.0,"vehicle_attitude.q[3]":0.0}]
    result=build_replay({"evidence_id":"EV-000000000001","inspection":{"samples":rows,"channels":[]}})
    assert result["has_geospatial"] and result["has_attitude"]
    assert abs(result["points"][0]["lat"]-19.1)<1e-6
    assert result["points"][0]["roll_deg"]==0
