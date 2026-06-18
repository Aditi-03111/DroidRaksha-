import asyncio, json, sys
sys.path.insert(0, '.')
from backend.db.database import init_db, engine
from sqlalchemy import text

async def check():
    await init_db()
    async with engine.connect() as conn:
        rows = await conn.execute(text(
            'SELECT id, filename, result_json FROM analyses ORDER BY created_at DESC LIMIT 3'
        ))
        for row in rows:
            result = json.loads(row[2]) if row[2] else {}
            xgb = result.get("xgboost", {})
            malbert = result.get("malbert", {})
            anomaly = result.get("anomaly", {})
            dynamic = result.get("dynamic", {})
            risk = result.get("risk", {})
            print(f"=== {row[1]} (id={row[0][:8]}) ===")
            print(f"  risk.score          = {risk.get('score')}")
            print(f"  xgboost.available   = {xgb.get('available')}")
            print(f"  xgboost.label       = {xgb.get('label')}")
            print(f"  xgboost.probability = {xgb.get('probability')}")
            print(f"  malbert.available   = {malbert.get('available')}")
            print(f"  malbert.label       = {malbert.get('label')}")
            print(f"  anomaly.model_used  = {anomaly.get('model_used')}")
            print(f"  dynamic present     = {dynamic is not None and bool(dynamic)}")
            print(f"  sandbox_available   = {dynamic.get('sandbox_available') if dynamic else 'N/A'}")
            print()

asyncio.run(check())
