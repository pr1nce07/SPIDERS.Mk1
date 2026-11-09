from __future__ import annotations
import math, re
from typing import Any

ALIASES = {
 'lat':('lat','latitude','gps_lat','gps.lat','gps_latitude','gps_coord[0]'),
 'lon':('lon','lng','longitude','gps_lon','gps.lng','gps_longitude','gps_coord[1]'),
 'alt':('alt','altitude','relative_alt','rel_alt','gps_alt','baro_alt','baroalt'),
 'roll':('roll','att_roll','roll_deg','roll_rad'),
 'pitch':('pitch','att_pitch','pitch_deg','pitch_rad'),
 'yaw':('yaw','heading','att_yaw','yaw_deg','yaw_rad'),
 'time':('timestamp','time','time_ms','time_us','timestamp_us','t','datetime'),
 'vx':('vx','vel_x','velocity_x','north_speed'), 'vy':('vy','vel_y','velocity_y','east_speed'), 'vz':('vz','vel_z','velocity_z'),
}
def _pick(row:dict, aliases:tuple):
    lower={str(k).lower():v for k,v in row.items()}
    for a in aliases:
        matches=[(k,v) for k,v in lower.items() if k==a or k.endswith("."+a) or k.endswith("_"+a)]
        if matches:
            key,value=matches[0]
            try:
                v=float(value)
                if not math.isfinite(v): return None
                # ArduPilot DataFlash and PX4 vehicle_gps_position use 1e-7 degrees.
                if (a in ("lat","latitude","gps_coord[0]") and abs(v)>90 and "gps" in key) or (a in ("lon","lng","longitude","gps_coord[1]") and abs(v)>180 and "gps" in key): v/=1e7
                if a in ("alt","altitude","relative_alt","rel_alt","gps_alt","baro_alt","baroalt") and ("vehicle_gps_position" in key or "global_position_int" in key): v/=1000.0
                return v
            except (TypeError,ValueError): return value
    return None

def _angle(row:dict, base:str):
    lower={str(k).lower():v for k,v in row.items()}
    for key in (base+'_deg',base, 'att_'+base, base+'_rad'):
        matches=[(k,v) for k,v in lower.items() if k==key or k.endswith("."+key) or k.endswith("_"+key)]
        if matches:
            actual,value=matches[0]
            try:
                value=float(value)
                if not math.isfinite(value): return None
                return math.degrees(value) if actual.endswith('_rad') else value
            except (TypeError,ValueError): return None
    # PX4 vehicle_attitude.q[0..3] is a quaternion (w,x,y,z).
    qkeys=[]
    for i in range(4):
        found=next((v for k,v in lower.items() if k.endswith(f"q[{i}]") or k.endswith(f"q_{i}")),None)
        if found is None: qkeys=[]; break
        qkeys.append(float(found))
    if len(qkeys)==4:
        w,x,y,z=qkeys
        if base=='roll': return math.degrees(math.atan2(2*(w*x+y*z),1-2*(x*x+y*y)))
        if base=='pitch': return math.degrees(math.asin(max(-1,min(1,2*(w*y-z*x)))))
        if base=='yaw': return math.degrees(math.atan2(2*(w*z+x*y),1-2*(y*y+z*z)))
    return None

def build_replay(evidence:dict[str,Any], max_points:int=5000)->dict[str,Any]:
    ins=evidence.get('inspection') or {}; rows=ins.get('samples') or []
    if not rows:
        # Derived custom-schema data is preferred when present by caller.
        return {'evidence_id':evidence['evidence_id'],'mode':'index-only','points':[],'channels':ins.get('channels',[]),'warnings':['No decoded sample rows are available for replay.'], 'coordinate_source':'none'}
    step=max(1,math.ceil(len(rows)/max_points)); points=[]
    for idx,row in enumerate(rows[::step]):
        if not isinstance(row,dict): continue
        lat=_pick(row,ALIASES['lat']); lon=_pick(row,ALIASES['lon']); alt=_pick(row,ALIASES['alt'])
        roll=_angle(row,'roll'); pitch=_angle(row,'pitch'); yaw=_angle(row,'yaw')
        t=_pick(row,ALIASES['time'])
        points.append({'index':idx*step,'time':t,'lat':lat,'lon':lon,'alt':alt,'roll_deg':roll,'pitch_deg':pitch,'yaw_deg':yaw,
          'vx':_pick(row,ALIASES['vx']),'vy':_pick(row,ALIASES['vy']),'vz':_pick(row,ALIASES['vz']), 'raw':row})
    geo=sum(p['lat'] is not None and p['lon'] is not None and -90<=p['lat']<=90 and -180<=p['lon']<=180 for p in points)
    att=sum(any(p[k] is not None for k in ('roll_deg','pitch_deg','yaw_deg')) for p in points)
    warnings=[]
    if not geo:warnings.append('No valid latitude/longitude pair: geographic path is unavailable; no map coordinates were fabricated.')
    if not att:warnings.append('No attitude channels: 3D orientation is unavailable; vehicle orientation is not inferred.')
    if any(p['time'] is None for p in points):warnings.append('Some or all timestamps are absent; replay uses sample index for navigation.')
    return {'evidence_id':evidence['evidence_id'],'mode':'recorded-data','sample_count':len(rows),'displayed_count':len(points),'downsample_factor':step,
      'coordinate_source':'recorded latitude/longitude' if geo else 'none','has_geospatial':bool(geo),'has_attitude':bool(att),
      'points':points,'channels':ins.get('channels',[]),'warnings':warnings,
      'provenance':'Values are copied from parser samples. Radians are converted only for explicitly named *_rad fields; all other angle units are preserved as supplied and require schema confirmation.'}
