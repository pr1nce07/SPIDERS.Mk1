from __future__ import annotations
import json
from pathlib import Path
from typing import Any

_CATALOG = Path(__file__).with_name('knowledge_base') / 'catalog.json'

def list_profiles():
    try:
        catalog=json.loads(_CATALOG.read_text(encoding='utf-8'))
        profiles=catalog.get('profiles',[])
    except Exception:
        profiles=[]
    normalized=[]
    for p in profiles:
        normalized.append({'id':p.get('id'),'name':p.get('name'),'kind':p.get('firmware_families',p.get('kind','reference')),
          'formats':p.get('log_formats',[]),'parameter_prefixes':p.get('parameter_prefixes',[]),
          'references':p.get('references',[]),'status':'reference-index','limitations':p.get('limitations','')})
    return {'schema_version':1,'profiles':normalized,'notice':'Profiles index parser/firmware references only. They do not assert aircraft identity, configuration, or physical performance values.'}

def validate_profile(profile:dict[str,Any]):
    name=str(profile.get('name','')).strip()
    if not name or len(name)>120: raise ValueError('profile name is required (max 120 chars)')
    actuators=profile.get('actuators',[]); sensors=profile.get('sensors',[])
    if not isinstance(actuators,list) or len(actuators)>64: raise ValueError('actuators must be a list of at most 64 items')
    if not isinstance(sensors,list) or len(sensors)>128: raise ValueError('sensors must be a list of at most 128 items')
    geometry=profile.get('geometry',{})
    if not isinstance(geometry,dict): raise ValueError('geometry must be an object')
    return {'id':str(profile.get('id') or 'custom-'+__import__('uuid').uuid4().hex[:10]),'name':name,
      'manufacturer':profile.get('manufacturer'),'model':profile.get('model'),'vehicle_type':profile.get('vehicle_type','unknown'),
      'flight_controller':profile.get('flight_controller'),'firmware':profile.get('firmware'),'actuators':actuators,
      'sensors':sensors,'geometry':geometry,'source':'investigator-supplied','verified':False}
