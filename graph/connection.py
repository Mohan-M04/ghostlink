"""FalkorDB connection helpers."""
import os
from dotenv import load_dotenv
load_dotenv()
def connect_graph():
    try:
        from falkordb import FalkorDB
    except ImportError as exc:
        raise RuntimeError("Install dependencies with: pip install -r requirements.txt") from exc
    kwargs={"host":os.getenv("FALKORDB_HOST","localhost"),"port":int(os.getenv("FALKORDB_PORT","6379"))}
    password=os.getenv("FALKORDB_PASSWORD","")
    if password: kwargs["password"]=password
    db=FalkorDB(**kwargs)
    return db, db.select_graph(os.getenv("GRAPH_NAME","ghostlink"))
