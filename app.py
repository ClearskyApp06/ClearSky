# app.py

import asyncio
import functools
import os
import sys
from datetime import datetime, timezone

import aiocron
import aiohttp
from quart import Quart, jsonify, request, session
from quart_cors import cors
from quart_rate_limiter import RateLimiter
from quart_schema import QuartSchema

import config_helper
import database_handler
import utils
from apis import api_blueprint
from apiv2 import blueprint
from config_helper import logger
from core import db_pool_acquired, dbs_connected, initialize
from environment import get_api_var
from errors import DatabaseConnectionError, NotFound
from helpers import (
    blocklist_24_failed,
    blocklist_failed,
    get_ip,
    get_ip_address,
    get_var_info,
    version,
)

# ======================================================================================================================
# ======================================== global variables // Set up logging ==========================================
config = config_helper.read_config()

title_name = "ClearSky"
if sys.platform == "Windows":
    os.system("title " + title_name)  # nosec
current_dir = os.getcwd()
log_version = "ClearSky Version: " + version
current_time = datetime.now(timezone.utc).strftime("%m%d%Y::%H:%M:%S")

try:
    username = os.getlogin()
except OSError:
    username = "Unknown"

app = Quart(__name__)
QuartSchema(app, convert_casing=True)
app.register_blueprint(api_blueprint)
app.register_blueprint(blueprint.bp, url_prefix="/api/v2")
rate_limiter = RateLimiter(app)
cors(app, allow_origin="*")

# Configure session secret key
app.secret_key = "your-secret-key"


# ======================================================================================================================
# ============================================= Main functions =========================================================
async def preprocess_status(identifier) -> bool:
    if not identifier:
        return False

    try:
        persona, status = await database_handler.identifier_exists_in_db(identifier)
        logger.debug(f"persona: {persona} status: {status}")
    except AttributeError:
        logger.error("db connection issue.")

        raise DatabaseConnectionError

    if persona is True and status is True:
        return True
    elif persona is True and status is False:
        logger.info(f"Account: {identifier} deleted")

        return False
    elif status is False and persona is False:
        logger.info(f"{identifier}: does not exist.")

        raise NotFound
    else:
        logger.info(f"Error page loaded for resolution failure using: {identifier}")

        return False


async def run_web_server() -> None:
    ip_address, port_address = await get_ip_address()

    if not ip_address or not port_address:
        logger.error("No IP or port configured.")
        sys.exit()

    logger.info(f"Web server starting at: {ip_address}:{port_address}")

    await app.run_task(host=ip_address, port=int(port_address))


async def first_run() -> None:
    while not db_pool_acquired.is_set():
        logger.info("db connection not acquired, waiting for established connection.")
        await asyncio.sleep(5)

    while True:
        if dbs_connected:
            blocklist_24_failed.clear()
            blocklist_failed.clear()

            tables = await database_handler.tables_exists()

            if tables:
                pass
                await database_handler.blocklists_updater()
                await database_handler.top_24blocklists_updater()
                await utils.update_block_statistics()
                await utils.update_total_users()

                break
            else:
                logger.warning("Tables do not exist in db.")
                sys.exit()

        await asyncio.sleep(30)


@aiocron.crontab("0 */12 * * *")  # Every 12 hours
async def schedule_stats_update() -> None:
    pass

    logger.info("Starting scheduled stats update.")

    if database_handler.blocklist_updater_status.is_set():
        logger.warning("Blocklist updater is already running.")
    else:
        await database_handler.blocklists_updater()

    if database_handler.blocklist_24_updater_status.is_set():
        logger.warning("Top 24 blocklist updater is already running.")
    else:
        await database_handler.top_24blocklists_updater()

    if utils.block_stats_status.is_set():
        logger.warning("Block stats updater is already running.")
    else:
        await utils.update_block_statistics()

    if utils.total_users_status.is_set():
        logger.warning("Total users updater is already running.")
    else:
        await utils.update_total_users()

    logger.info("Scheduled stats update complete.")


@aiocron.crontab("*/10 * * * *")  # Every 10 mins
async def schedule_total_users_update() -> None:
    pass

    if utils.total_users_status.is_set():
        logger.warning("Total users updater is already running.")

        return

    logger.info("Starting scheduled total users update.")

    await utils.update_total_users()

    logger.info("Scheduled total users update complete.")


def api_key_required(key_type) -> callable:
    def decorator(func) -> callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> callable:
            api_environment = get_api_var()

            provided_api_key = request.headers.get("X-API-Key")

            api_keys = await database_handler.get_api_keys(api_environment, key_type, provided_api_key)
            try:
                if (
                    provided_api_key not in api_keys.get("key")
                    or api_keys.get("valid") is False
                    or api_keys.get(key_type) is False
                ):
                    ip = await get_ip()
                    logger.warning(f"<< {ip}: given key:{provided_api_key} Unauthorized API access.")
                    session["authenticated"] = False

                    return (
                        "Unauthorized",
                        401,
                    )  # Return an error response if the API key is not valid
            except AttributeError:
                logger.error(f"API key not found for type: {key_type}")
                session["authenticated"] = False

                return "Unauthorized", 401
            else:
                logger.info(f"Valid key {provided_api_key} for type: {key_type}")

                session["authenticated"] = True  # Set to True if authenticated

            return await func(*args, **kwargs)

        return wrapper

    return decorator


@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify(error="ratelimit exceeded", message=str(e.description)), 429


async def fetch_and_push_data():
    var_info = await get_var_info()

    api_key = var_info.get("api_key")
    push_server = var_info.get("push_server")
    self_server = var_info.get("self_server")

    logger.info(f"API key: {api_key} | Push server: {push_server} | Self server: {self_server}")

    if api_key is not None:
        try:
            fetch_api_map = {
                "top_blocked": f"{self_server}/api/v1/auth/lists/fun-facts",
                "top_24_blocked": f"{self_server}/api/v1/auth/lists/funer-facts",
                "block_stats": f"{self_server}/api/v1/auth/lists/block-stats",
                "total_users": f"{self_server}/api/v1/auth/total-users",
            }
            send_api_map = {
                "top_blocked": f"{push_server}/api/v1/base/reporting/stats-cache/top-blocked",
                "top_24_blocked": f"{push_server}/api/v1/base/reporting/stats-cache/top-24-blocked",
                "block_stats": f"{push_server}/api/v1/base/reporting/stats-cache/block-stats",
                "total_users": f"{push_server}/api/v1/base/reporting/stats-cache/total-users",
            }
            headers = {"X-API-Key": f"{api_key}"}

            async with aiohttp.ClientSession(headers=headers) as get_session:
                for (fetch_name, fetch_api), (_send_name, send_api) in zip(
                    fetch_api_map.items(), send_api_map.items(), strict=False
                ):
                    logger.info(f"Fetching data from {fetch_name} API")

                    async with get_session.get(fetch_api) as internal_response:
                        if internal_response.status == 200:
                            internal_data = await internal_response.json()
                            if "timeLeft" in internal_data["data"]:
                                logger.info(f"{fetch_name} Data not ready, skipping.")
                            else:
                                async with get_session.post(send_api, json=internal_data) as response:
                                    if response.status == 200:
                                        logger.info(f"Data successfully pushed to {send_api}")
                                    else:
                                        logger.error("Failed to push data to the destination server")
                                        continue
                        else:
                            logger.error(f"Failed to fetch data from {fetch_api}")
                            continue
        except Exception as e:
            logger.error(f"An error occurred: {e}")
    else:
        logger.error("PUSH not executed, no API key configured.")


# Schedule the task to run every hour
@aiocron.crontab("0 * * * *")
async def schedule_data_push():
    logger.info("Starting scheduled data push.")
    await fetch_and_push_data()


# ======================================================================================================================
# =============================================== Main Logic ===========================================================
async def main():
    logger.info(log_version)
    logger.debug("Ran from: " + current_dir)
    logger.debug("Ran by: " + username)
    logger.debug("Ran at: " + str(current_time))
    logger.info("File Log level: " + str(config.get("handler_fileHandler", "level")))
    logger.info("Stdout Log level: " + str(config.get("handler_consoleHandler", "level")))

    initialize_task = asyncio.create_task(initialize())
    run_web_server_task = asyncio.create_task(run_web_server())

    await initialize_task

    await asyncio.gather(run_web_server_task, first_run())


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
