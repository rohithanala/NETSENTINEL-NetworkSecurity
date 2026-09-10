import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent/".env")
class Config:
 SECRET_KEY=os.getenv("SECRET_KEY","netsentinel-dev")
 SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL",f"sqlite:///{Path(__file__).parent/'netsentinel.db'}")
 SQLALCHEMY_TRACK_MODIFICATIONS=False
 MONITOR_INTERFACE=os.getenv("MONITOR_INTERFACE","")
 MONITOR_MODE=os.getenv("MONITOR_MODE","LIVE").upper()
 PORT_SCAN_WINDOW=int(os.getenv("PORT_SCAN_WINDOW","10"))
 PORT_SCAN_THRESHOLD=int(os.getenv("PORT_SCAN_THRESHOLD","15"))
 CONNECTION_RATE_WINDOW=int(os.getenv("CONNECTION_RATE_WINDOW","10"))
 CONNECTION_RATE_THRESHOLD=int(os.getenv("CONNECTION_RATE_THRESHOLD","50"))
 ALERT_COOLDOWN_SECONDS=int(os.getenv("ALERT_COOLDOWN_SECONDS","10"))
