import asyncio, sys
sys.path.insert(0, '.')
from backend.db.database import init_db, engine
from sqlalchemy import text

async def clear():
    await init_db()
    async with engine.connect() as conn:
        # Clear the analyses table to remove stale cache records
        r1 = await conn.execute(text("DELETE FROM analyses"))
        r2 = await conn.execute(text("DELETE FROM pcap_analyses"))
        await conn.commit()
        print(f"Cleared analyses table ({r1.rowcount} rows deleted)")
        print(f"Cleared pcap_analyses table ({r2.rowcount} rows deleted)")

asyncio.run(clear())
