import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from db_api.database import db


async def main():
    async with AsyncSession(db.engine) as session:
        await session.execute(
            text("""
                ALTER TABLE accounts
                ADD COLUMN completed BOOLEAN DEFAULT FALSE;
            """)
        )
        await session.commit()
        await session.close()

    print('Migration completed.')

asyncio.run(main())
