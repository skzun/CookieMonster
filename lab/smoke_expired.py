import sys
sys.path.insert(0, r"D:\CookieMonster")

import threading

from http.server import HTTPServer

from cookiemonster.store.db import Store
import click

from lab.mock_app import Handler

srv = HTTPServer(("127.0.0.1", 0), Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

store = Store(r"D:\CookieMonster\store.db")
store.init()
conn = store._connect()
conn.execute("DELETE FROM victims WHERE dir_name = '__lab_synth__'")
conn.commit()
conn.close()

with store.batch() as conn:
    vid = store.upsert_victim(conn, "__lab_synth__", "Cookies",
                               "lab://synthetic", wipe=True)
    conn.execute(
        "INSERT INTO cookies (victim_id, browser, profile, name, value, domain,"
        " path, secure, host_only, http_only, expires_epoch, source_file,"
        " same_site, partitioned, attrs)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (vid, "lab", "synth", "session", "EXPIRED", "127.0.0.1", "/",
         0, 0, 0, 0, "lab://synthetic", "unknown", 0, '{}'),
    )
    store.recompute_domains(conn, vid)

from cookiemonster.cli import check as check_cmd

with click.Context(check_cmd) as ctx:
    ctx.invoke(check_cmd,
               db_path=r"D:\CookieMonster\store.db", victim=vid,
               domain="127.0.0.1",
               url=f"http://127.0.0.1:{port}/",
               channel="httpx", req_path="/", shot_dir=None,
               allow_unsafe_scope=True, replay_mode="strict")

srv.shutdown()