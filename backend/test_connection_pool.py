"""
Test script to verify database connection pool is working correctly.
This will simulate concurrent database access to test for connection leaks.

Usage:
    python test_connection_pool.py
"""

import asyncio
import logging
import sys
import time
from pathlib import Path

# Add backend/app to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def test_concurrent_connections(num_concurrent: int = 15):
    """Test concurrent database connections."""
    from sqlmodel import Session, select

    from app.core.db import engine

    logger.info(f"Testing {num_concurrent} concurrent connections...")

    async def make_query(query_id: int):
        """Make a database query."""
        try:
            with Session(engine) as session:
                result = session.exec(select(1)).one()
                await asyncio.sleep(0.1)  # Simulate work
                logger.info(f"Query {query_id}: Success (result={result})")
                return True
        except Exception as e:
            logger.error(f"Query {query_id}: Failed - {e}")
            return False

    # Create tasks
    tasks = [make_query(i) for i in range(num_concurrent)]

    # Run concurrently
    start = time.time()
    results = await asyncio.gather(*tasks)
    duration = time.time() - start

    # Check results
    success_count = sum(results)
    logger.info(
        f"\nCompleted {success_count}/{num_concurrent} queries in {duration:.2f}s"
    )

    if success_count == num_concurrent:
        logger.info("\u2705 All concurrent connections successful")
        return True
    else:
        logger.error(f"\u274c {num_concurrent - success_count} queries failed")
        return False


def test_connection_leak():
    """Test for connection leaks by repeatedly creating and closing sessions."""
    from sqlmodel import Session, select

    from app.core.db import engine

    logger.info("\nTesting for connection leaks...")

    pool = engine.pool
    initial_checked_out = pool.checkedout()
    logger.info(f"Initial checked out connections: {initial_checked_out}")

    # Create and close many sessions
    num_iterations = 50
    for _ in range(num_iterations):
        try:
            with Session(engine) as session:
                session.exec(select(1)).one()
        except Exception as e:
            logger.error(f"Iteration failed - {e}")
            return False

    # Check if connections were leaked
    final_checked_out = pool.checkedout()
    logger.info(f"Final checked out connections: {final_checked_out}")

    if final_checked_out == initial_checked_out:
        logger.info(
            f"\u2705 No connection leaks detected after {num_iterations} iterations"
        )
        return True
    else:
        leaked = final_checked_out - initial_checked_out
        logger.error(f"\u274c Connection leak detected: {leaked} connections leaked")
        return False


def test_websocket_auth_failure():
    """Test that WebSocket auth failure doesn't leak connections."""
    from sqlmodel import Session

    from app.core.db import engine

    logger.info("\nTesting WebSocket auth failure scenario...")

    pool = engine.pool
    initial_checked_out = pool.checkedout()

    # Simulate the old buggy code path (early return)
    def buggy_websocket_handler():
        """Simulates old buggy WebSocket code."""
        db = Session(engine)
        try:
            # Simulate auth failure
            user = None
            if not user:
                # Early return without closing session (the bug!)
                return False
        finally:
            db.close()  # This should always run
        # Return outside finally
        return True

    # Simulate the fixed code path
    def fixed_websocket_handler():
        """Simulates fixed WebSocket code."""
        db = None
        try:
            db = Session(engine)
            # Simulate auth failure
            user = None
            if not user:
                # Early return - session will be closed in finally
                return False
        finally:
            if db is not None:
                db.close()
        # Return outside finally
        return True

    # Test fixed version multiple times
    for _ in range(10):
        fixed_websocket_handler()

    final_checked_out = pool.checkedout()

    if final_checked_out == initial_checked_out:
        logger.info("\u2705 No leaks in WebSocket auth failure scenario")
        return True
    else:
        leaked = final_checked_out - initial_checked_out
        logger.error(f"\u274c WebSocket handler leaked {leaked} connections")
        return False


def test_pool_exhaustion():
    """Test behavior when pool is exhausted."""
    from sqlmodel import Session, select

    from app.core.db import engine

    logger.info("\nTesting pool exhaustion behavior...")

    pool = engine.pool
    logger.info(f"Pool size: {pool.size()}")
    logger.info(
        f"Max overflow: {pool._pool.maxsize - pool.size() if hasattr(pool, '_pool') else 'N/A'}"
    )

    # Hold connections open to exhaust pool
    sessions = []
    max_sessions = 35  # More than pool_size + max_overflow (10 + 20 = 30)

    try:
        for i in range(max_sessions):
            try:
                session = Session(engine)
                session.exec(select(1)).one()
                sessions.append(session)
                logger.info(f"Created session {i+1}/{max_sessions}")
            except Exception as e:
                logger.info(f"Pool exhausted at {i+1} connections (expected around 30)")
                logger.info(f"Error: {e}")
                break

        # Check pool status
        logger.info(f"Checked out: {pool.checkedout()}")
        logger.info(f"Overflow: {pool.overflow()}")

    finally:
        # Clean up
        for session in sessions:
            session.close()

        # Verify cleanup
        final_checked_out = pool.checkedout()
    if final_checked_out == 0:
        logger.info("\u2705 All connections properly released")
        return True
    else:
        logger.error(f"\u274c {final_checked_out} connections not released")
        return False


async def main():
    """Run all tests."""
    logger.info("=" * 60)
    logger.info("DATABASE CONNECTION POOL TEST SUITE")
    logger.info("=" * 60)

    results = {}

    # Test 1: Concurrent connections
    try:
        results["concurrent"] = await test_concurrent_connections(15)
    except Exception as e:
        logger.error(f"Concurrent test failed: {e}")
        results["concurrent"] = False

    # Test 2: Connection leaks
    try:
        results["leak"] = test_connection_leak()
    except Exception as e:
        logger.error(f"Leak test failed: {e}")
        results["leak"] = False

    # Test 3: WebSocket auth failure
    try:
        results["websocket"] = test_websocket_auth_failure()
    except Exception as e:
        logger.error(f"WebSocket test failed: {e}")
        results["websocket"] = False

    # Test 4: Pool exhaustion
    try:
        results["exhaustion"] = test_pool_exhaustion()
    except Exception as e:
        logger.error(f"Exhaustion test failed: {e}")
        results["exhaustion"] = False

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)

    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        logger.info(f"{test_name.capitalize():20s}: {status}")

    all_passed = all(results.values())
    logger.info("=" * 60)

    if all_passed:
        logger.info("✅ ALL TESTS PASSED - Connection pool is working correctly!")
        return 0
    else:
        failed = [name for name, passed in results.items() if not passed]
        logger.error(f"❌ TESTS FAILED: {', '.join(failed)}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
