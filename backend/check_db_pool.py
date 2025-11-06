"""
Script to check database connection pool status.
Run this to diagnose connection pool issues.

Usage:
    python check_db_pool.py
"""

import logging
import sys
from pathlib import Path

# Add backend/app to Python path
backend_dir = Path(__file__).parent
app_dir = backend_dir / "app"
sys.path.insert(0, str(backend_dir))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_pool_status():
    """Check the current database connection pool status."""
    from app.core.db import engine

    pool = engine.pool

    logger.info("=" * 60)
    logger.info("DATABASE CONNECTION POOL STATUS")
    logger.info("=" * 60)

    # Get pool statistics
    logger.info(f"Pool size: {pool.size()}")
    logger.info(f"Checked out connections: {pool.checkedout()}")
    logger.info(f"Overflow connections: {pool.overflow()}")
    logger.info(f"Checked in connections: {pool.checkedin()}")

    # Get pool configuration
    logger.info("\nPool Configuration:")
    logger.info(
        f"  Max pool size: {pool._pool.maxsize if hasattr(pool, '_pool') else 'N/A'}"
    )
    logger.info(f"  Pool class: {pool.__class__.__name__}")

    # Check for leaked connections
    checked_out = pool.checkedout()
    if checked_out > 0:
        logger.warning(
            f"\n⚠️  WARNING: {checked_out} connections are currently checked out"
        )
        logger.warning(
            "This is normal during active requests, but if this number stays high,"
        )
        logger.warning("you may have connection leaks.")
    else:
        logger.info("\n✅ No connections currently checked out (pool is clean)")

    # Calculate usage percentage
    pool_size = pool.size()
    if pool_size > 0:
        usage_percent = (checked_out / pool_size) * 100
        logger.info(f"\nPool usage: {usage_percent:.1f}%")

        if usage_percent > 80:
            logger.warning(
                "⚠️  Pool usage is high (>80%). Consider increasing pool_size."
            )
        elif usage_percent > 50:
            logger.info("ℹ️  Pool usage is moderate (>50%).")

    logger.info("=" * 60)


def test_connection():
    """Test creating and closing a connection."""
    from sqlmodel import Session, select

    from app.core.db import engine

    logger.info("\nTesting connection creation and cleanup...")

    try:
        with Session(engine) as session:
            result = session.exec(select(1)).one()
            logger.info(f"✅ Connection test successful (result: {result})")
    except Exception as e:
        logger.error(f"❌ Connection test failed: {e}")
        raise


def check_for_long_running_queries():
    """Check for long-running queries that might be holding connections."""
    from sqlmodel import Session

    from app.core.db import engine

    logger.info("\nChecking for long-running queries...")

    try:
        with Session(engine) as session:
            # PostgreSQL specific query
            query = """
                SELECT
                    pid,
                    now() - query_start as duration,
                    state,
                    query
                FROM pg_stat_activity
                WHERE state != 'idle'
                    AND query NOT LIKE '%pg_stat_activity%'
                ORDER BY duration DESC
                LIMIT 10
            """
            try:
                result = session.exec(query).all()  # type: ignore
                if result:
                    logger.info("Long-running queries found:")
                    for row in result:
                        logger.info(
                            f"  PID: {row[0]}, Duration: {row[1]}, State: {row[2]}"
                        )
                        logger.info(f"  Query: {row[3][:100]}...")
                else:
                    logger.info("✅ No long-running queries found")
            except Exception as e:
                logger.info(f"ℹ️  Could not check for long-running queries: {e}")
                logger.info("(This is normal if not using PostgreSQL)")
    except Exception as e:
        logger.error(f"❌ Failed to check for long-running queries: {e}")


def main():
    """Main function."""
    logger.info("Database Connection Pool Diagnostic Tool\n")

    try:
        # Check pool status
        check_pool_status()

        # Test connection
        test_connection()

        # Check for long-running queries
        check_for_long_running_queries()

        logger.info("\n✅ Diagnostic completed successfully")

    except Exception as e:
        logger.error(f"\n❌ Diagnostic failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
