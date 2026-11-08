"""Start the SPIDERS.Mk1 backend (binds to 127.0.0.1 unless remote mode is configured)."""
import uvicorn

from app.config import Config

if __name__ == "__main__":
    cfg = Config.load()
    host = cfg.get("security.bind_host", "127.0.0.1")
    if not cfg.get("security.remote_mode", False) and host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing to bind a non-loopback address without security.remote_mode (authentication) enabled")
    ssl = {}
    if cfg.get("security.remote_mode", False):
        if not (cfg.get("security.tls_cert") and cfg.get("security.tls_key")):
            raise SystemExit("remote mode requires security.tls_cert and security.tls_key")
        ssl = {"ssl_certfile": cfg.get("security.tls_cert"), "ssl_keyfile": cfg.get("security.tls_key")}
    uvicorn.run("app.main:app", host=host, port=int(cfg.get("security.port", 8600)), log_level="info", **ssl)
