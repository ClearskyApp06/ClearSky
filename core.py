# core.py
import asyncio
import csv
import functools
import io
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import aiofiles
import aiofiles.os
import aiohttp
import httpx
import pytz
from quart import jsonify, request, session

import database_handler
import helpers
import on_wire
import utils
from config_helper import logger, upload_limit_mb
from environment import get_api_var
from errors import (
    BadRequest,
    DatabaseConnectionError,
    ExceedsFileSizeLimit,
    FileNameExists,
    NotFound,
    NotImplement,
    Unauthorized,
)
from helpers import (
    blocklist_24_failed,
    blocklist_failed,
    get_ip,
    get_ip_address,
    get_time_since,
    get_var_info,
    runtime,
    version,
)

# ======================================================================================================================
# ============================================== global variables ======================================================
fun_start_time = None
funer_start_time = None
total_start_time = None
block_stats_app_start_time = None
dbs_connected = None
db_pool_acquired = asyncio.Event()


# ======================================================================================================================
# ============================================== utility functions =====================================================
async def sanitization(identifier) -> str:
    identifier = identifier.lower()
    identifier = identifier.strip()
    identifier = identifier.replace("@", "")

    return identifier


async def uri_sanitization(uri) -> str | None:
    if uri:
        if "at://" in uri:
            if "app.bsky.graph.listitem" in uri:
                url = await database_handler.get_listitem_url(uri)

                return url
            elif "app.bsky.graph.listblock" in uri:
                url = await database_handler.get_listblock_url(uri)

                return url
            elif "app.bsky.graph.list" in uri:
                url = await utils.list_uri_to_url(uri)

                return url
            elif "app.bsky.feed.post" in uri:
                base_url = "https://bsky.app/profile"
                did_start = uri.find("did:")
                did_end = uri.find("/", did_start)
                did = uri[did_start:did_end]
                rkey = uri.split("/")[-1]
                url = f"{base_url}/{did}/post/{rkey}"

                return url
            elif "app.bsky.actor.profile" in uri:
                base_url = "https://bsky.app/profile"
                did_start = uri.find("did:")
                did_end = uri.find("/", did_start)
                did = uri[did_start:did_end]
                url = f"{base_url}/{did}"

                return url
            elif "app.bsky.feed.generator" in uri:
                base_url = "https://bsky.app/profile"
                did_start = uri.find("did:")
                did_end = uri.find("/", did_start)
                did = uri[did_start:did_end]
                rkey = uri.split("/")[-1]
                url = f"{base_url}/{did}/feed/{rkey}"

                return url
            elif "app.bsky.graph.block" in uri:
                response = await database_handler.get_block_row(uri)

                return response
            elif "app.bsky.graph.starterpack" in uri:
                base_url = "https://bsky.app/starter-pack"
                did_start = uri.find("did:")
                did_end = uri.find("/", did_start)
                did = uri[did_start:did_end]
                rkey = uri.split("/")[-1]
                url = f"{base_url}/{did}/{rkey}"

                return url
            else:
                raise NotFound
        else:
            raise BadRequest
    else:
        raise BadRequest


async def initialize() -> None:
    global db_pool_acquired, dbs_connected

    utils.total_users_status.set()
    utils.block_stats_status.set()
    database_handler.blocklist_updater_status.set()
    database_handler.blocklist_24_updater_status.set()

    # Creates connection pool for dbs if connection made
    dbs_connected = await database_handler.create_connection_pools(database_handler.database_config)

    log_warning_once = True

    if dbs_connected is None:
        while True:
            dbs_connected = await database_handler.create_connection_pools(database_handler.database_config)

            if dbs_connected:
                db_pool_acquired.set()

                if not log_warning_once:
                    logger.warning("db connection established.")

                logger.info("Initialized.")
                break
            else:
                if log_warning_once:
                    logger.warning("db not operational.")

                    log_warning_once = False

                    blocklist_24_failed.set()
                    blocklist_failed.set()

                logger.info("Waiting for db connection.")
                await asyncio.sleep(30)
    else:
        db_pool_acquired.set()

    logger.info("Initialized.")

    for db in dbs_connected:
        logger.info(f"{db} connected.")

    logger.info(f"read db(s): {database_handler.read_dbs}")

    write_db = database_handler.get_connection_pool("write")

    logger.info(f"write db: {write_db}")


async def pre_process_identifier(identifier) -> tuple[str | None, str | None]:
    did_identifier = None
    handle_identifier = None

    if not identifier:  # If form is submitted without anything in the identifier return intentional error
        return did_identifier, handle_identifier

    # Check if did or handle exists before processing
    if utils.is_did(identifier):
        if not await database_handler.local_db():
            try:
                did_identifier = identifier
                handle_identifier = await asyncio.wait_for(utils.use_handle(identifier), timeout=5)
            except TimeoutError:
                # handle_identifier = None
                logger.warning("resolution failed, possible connection issue.")
                did_identifier = identifier
                handle_identifier = await database_handler.get_user_handle(identifier)
                if handle_identifier is not None:
                    logger.info("resolved did using db")
        else:
            did_identifier = identifier
            handle_identifier = await database_handler.get_user_handle(identifier)
    elif utils.is_handle(identifier):
        if not await database_handler.local_db():
            try:
                handle_identifier = identifier
                did_identifier = await asyncio.wait_for(utils.use_did(identifier), timeout=5)
            except TimeoutError:
                # did_identifier = None
                logger.warning("resolution failed, possible connection issue.")
                handle_identifier = identifier
                did_identifier = await database_handler.get_user_did(identifier)
                if did_identifier is not None:
                    logger.info("resolved handle using db")
        else:
            handle_identifier = identifier
            did_identifier = await database_handler.get_user_did(identifier)
    else:
        did_identifier = None
        handle_identifier = None

    return did_identifier, handle_identifier


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

                    raise Unauthorized("Unauthorized")
            except AttributeError:
                logger.error(f"API key not found for type: {key_type}")
                raise Unauthorized("Unauthorized")
            else:
                logger.info(f"Valid key {provided_api_key} for type: {key_type}")

                session["authenticated"] = True  # Set to True if authenticated

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# ======================================================================================================================
# ============================================ API Services Functions ==================================================
async def get_blocklist(client_identifier: str, page: int) -> dict[str, Any]:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - blocklist request: {identifier}")

    try:
        if identifier:
            did_identifier, handle_identifier = await pre_process_identifier(identifier)
            status = await preprocess_status(did_identifier)

            if did_identifier and handle_identifier and status:
                items_per_page = 100
                offset = (page - 1) * items_per_page

                blocklist, count, pages = await utils.process_user_block_list(
                    did_identifier, limit=items_per_page, offset=offset
                )
                formatted_count = f"{count:,}"

                blocklist_data = {
                    "blocklist": blocklist,
                    "count": formatted_count,
                    "pages": pages,
                }
            else:
                blocklist = None
                count = 0

                blocklist_data = {"blocklist": blocklist, "count": count}
        else:
            identifier = "Missing parameter"
            raise BadRequest(identifier, identifier)
    finally:
        logger.info(f">> {session_ip} - {api_key} - blocklist result returned: {identifier}")

    return blocklist_data


async def get_single_blocklist(client_identifier: str, page: int) -> tuple[str, bool, dict[str, Any]]:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - single blocklist request: {identifier}")

    try:
        if identifier:
            did_identifier, handle_identifier = await pre_process_identifier(identifier)
            status = await preprocess_status(did_identifier)

            if did_identifier and handle_identifier and status:
                items_per_page = 100
                offset = (page - 1) * items_per_page

                blocklist, count, pages = await database_handler.get_single_user_blocks(
                    did_identifier, limit=items_per_page, offset=offset
                )
                formatted_count = f"{count:,}"

                blocklist_data = {
                    "blocklist": blocklist,
                    "count": formatted_count,
                    "pages": pages,
                }
            else:
                blocklist_data = None
                count = 0

                blocklist_data = {"blocklist": blocklist_data, "count": count}

            return identifier, status, blocklist_data
        else:
            identifier = "Missing parameter"
            raise BadRequest(identifier, identifier)
    finally:
        logger.info(f">> {session_ip} - {api_key} - single blocklist result returned: {identifier}")


async def get_in_common_blocklist(client_identifier: str) -> tuple[str, dict[str, Any]]:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - in-common blocklist request: {identifier}")

    try:
        if identifier:
            did_identifier, handle_identifier = await pre_process_identifier(identifier)
            status = await preprocess_status(did_identifier)

            if did_identifier and handle_identifier and status:
                blocklist_data = await database_handler.get_similar_users(did_identifier)
            else:
                blocklist_data = None

            common_list = {"inCommonList": blocklist_data}

            return identifier, common_list
        else:
            identifier = "Missing parameter"
            raise BadRequest(identifier, identifier)
    finally:
        logger.info(f">> {session_ip} - {api_key} - in-common blocklist result returned: {identifier}")


async def get_in_common_blocked(client_identifier: str) -> tuple[str, dict[str, Any]]:
    common_list = None

    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - in-common blocked request: {identifier}")
    raise NotImplement()

    try:
        if identifier:
            did_identifier, handle_identifier = await pre_process_identifier(identifier)
            status = await preprocess_status(did_identifier)

            if did_identifier and handle_identifier and status:
                blocklist_data = await database_handler.get_similar_blocked_by(did_identifier)
                # formatted_count = '{:,}'.format(count)

            else:
                blocklist_data = None

            common_list = {"inCommonList": blocklist_data}

            return identifier, common_list
        else:
            identifier = "Missing parameter"
            raise BadRequest(identifier, identifier)
    finally:
        logger.info(f">> {session_ip} - {api_key} - in-common blocked result returned: {identifier}")


async def convert_uri_to_url(uri: str) -> dict[str, Any]:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    url = await uri_sanitization(uri)

    logger.info(f"<< {session_ip} - {api_key} - get at-uri conversion request: {uri}")

    try:
        if url:
            url_data = {"url": url}
            return url_data
        else:
            result = "Malformed parameter"
            return BadRequest(result, result)
    finally:
        logger.info(f">> {session_ip} - {api_key} - at-uri conversion result returned: {uri}")


async def get_total_users():
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")
    remaining_time = "not yet determined"

    logger.info(f"<< {session_ip} - {api_key} - total users request")

    if utils.total_users_status.is_set():
        logger.info("Total users count is being updated.")

        process_time = utils.total_users_process_time

        start_time = total_start_time if utils.total_users_start_time is None else utils.total_users_start_time

        if process_time is None:
            remaining_time = "not yet determined"
        else:
            time_elapsed = datetime.now(timezone.utc) - start_time

            if time_elapsed < process_time:
                # Calculate hours and minutes left
                time_difference = process_time - time_elapsed
                seconds_left = time_difference.total_seconds()
                minutes_left = seconds_left / 60
                # hours = minutes // 60
                remaining_seconds = seconds_left % 60

                if minutes_left > 1:
                    remaining_time = f"{round(minutes_left)} mins {round(remaining_seconds)} seconds"
                elif seconds_left > 0:
                    remaining_time = f"{round(seconds_left)} seconds"
            else:
                remaining_time = "just finished"

        timing = {"timeLeft": remaining_time}
        data = {"data": timing}

        return jsonify(data)

    total_count = utils.total_users_cache.get("total_users")
    active_count = utils.total_active_users_cache.get("total_active_users")
    deleted_count = utils.total_deleted_users_cache.get("total_deleted_users")

    formatted_active_count = f"{active_count:,}"
    formatted_total_count = f"{total_count:,}"
    formatted_deleted_count = f"{deleted_count:,}"

    logger.debug(f"{session_ip} > {api_key} | total users count: {formatted_total_count}")
    logger.debug(f"{session_ip} > {api_key} | total active users count: {formatted_active_count}")
    logger.debug(f"{session_ip} > {api_key} | total deleted users count: {formatted_deleted_count}")

    count_data = {
        "active_count": {
            "value": formatted_active_count,
            "displayName": "Active Users",
        },
        "total_count": {
            "value": formatted_total_count,
            "displayName": "Total Users",
        },
        "deleted_count": {
            "value": formatted_deleted_count,
            "displayName": "Deleted Users",
        },
        "as of": utils.total_users_as_of_time,
    }

    data = {"data": count_data}

    logger.info(f">> {session_ip} - {api_key} - total users result returned")

    return jsonify(data)


async def get_did_info(client_identifier: str) -> dict[str, Any] | None:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - get did request: {identifier}")

    try:
        if identifier:
            did_identifier, handle_identifier = await pre_process_identifier(identifier)
            status = await preprocess_status(did_identifier)

            if did_identifier and handle_identifier and status:
                pds = await on_wire.get_pds(did_identifier)

                avatar_id = await on_wire.get_avatar_id(did_identifier)

                did_data = {
                    "identifier": identifier,
                    "did_identifier": did_identifier,
                    "user_url": f"https://bsky.app/profile/{did_identifier}",
                    "avatar_url": f"https://cdn.bsky.app/img/avatar/plain/{did_identifier}/{avatar_id}",
                    "pds": pds,
                }
            else:
                did_data = None

            return did_data
        else:
            identifier = "Missing parameter"
            raise BadRequest(identifier, identifier)
    finally:
        logger.info(f">> {session_ip} - {api_key} - did result returned: {identifier}")


async def get_handle_info(client_identifier: str) -> dict[str, Any] | None:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - get handle request: {identifier}")

    try:
        if identifier:
            did_identifier, handle_identifier = await pre_process_identifier(identifier)
            status = await preprocess_status(did_identifier)

            if did_identifier and handle_identifier and status:
                pds = await on_wire.get_pds(did_identifier)

                avatar_id = await on_wire.get_avatar_id(did_identifier)

                handle_data = {
                    "identifier": identifier,
                    "handle_identifier": handle_identifier,
                    "user_url": f"https://bsky.app/profile/{did_identifier}",
                    "avatar_url": f"https://cdn.bsky.app/img/avatar/plain/{did_identifier}/{avatar_id}",
                    "pds": pds,
                }
            else:
                handle_data = None

            return handle_data
        else:
            identifier = "Missing parameter"
            raise BadRequest(identifier, identifier)
    finally:
        logger.info(f">> {session_ip} - {api_key} - handle result returned: {identifier}")


async def get_handle_history_info(client_identifier) -> jsonify:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - get handle history request: {identifier}")

    if identifier:
        did_identifier, handle_identifier = await pre_process_identifier(identifier)
        status = await preprocess_status(did_identifier)

        if did_identifier and handle_identifier and status:
            handle_history = await utils.get_handle_history(did_identifier)

            handle_history_data = {
                "identifier": identifier,
                "handle_history": handle_history,
            }
        else:
            handle_history_data = None

        data = {"data": handle_history_data}
    else:
        identifier = "Missing parameter"
        result = "Missing parameter"
        block_data = {"error": result}
        data = {"data": block_data}

    logger.info(f">> {session_ip} - {api_key} - handle history result returned: {identifier}")

    return jsonify(data)


async def get_list_info(client_identifier) -> jsonify:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - get mute/block list request: {identifier}")

    if identifier:
        did_identifier, handle_identifier = await pre_process_identifier(identifier)
        status = await preprocess_status(did_identifier)

        if did_identifier and handle_identifier and status:
            mute_lists = await database_handler.get_mutelists(did_identifier)

            list_data = {"identifier": identifier, "lists": mute_lists}
        else:
            list_data = None

        data = {"identifier": identifier, "data": list_data}
    else:
        identifier = "Missing parameter"
        result = "Missing parameter"
        block_data = {"error": result}
        data = {"data": block_data}

    logger.info(f">> {session_ip} - {api_key} - mute/block list result returned: {identifier}")

    return jsonify(data)


async def get_moderation_lists(input_name, page) -> jsonify:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"<< {session_ip} - {api_key} - get moderation list request: {input_name}")

    if input_name:
        items_per_page = 100
        offset = (page - 1) * items_per_page

        name = input_name.lower()

        list_data, pages = await database_handler.get_moderation_list(name, limit=items_per_page, offset=offset)

        sub_data = {"lists": list_data, "pages": pages}

        data = {"input": name, "data": sub_data}
    else:
        input_name = "Missing parameter"
        result = "Missing parameter"
        block_data = {"error": result}
        data = {"data": block_data}

    logger.info(f">> {session_ip} - {api_key} - mute/block list result returned: {input_name}")

    return jsonify(data)


async def get_blocked_search(client_identifier, search_identifier) -> jsonify:
    api_key = request.headers.get("X-API-Key")
    session_ip = await get_ip()

    client_identifier = await sanitization(client_identifier)
    search_identifier = await sanitization(search_identifier)

    logger.info(
        f"<< {session_ip} - {api_key} - blocklist[blocked] search request: {client_identifier}:{search_identifier}"
    )

    if client_identifier and search_identifier:
        client_is_handle = utils.is_handle(client_identifier)
        search_is_handle = utils.is_handle(search_identifier)

        if client_is_handle and search_is_handle:
            result = await database_handler.blocklist_search(client_identifier, search_identifier, switch="blocked")
        else:
            result = None

        block_data = result if result else None

        data = {"data": block_data}
    else:
        if not client_identifier:
            client_identifier = "Missing parameter"
        if not search_identifier:
            search_identifier = "Missing parameter"
        result = "Missing parameter"
        block_data = {"error": result}
        data = {"data": block_data}

    logger.info(
        f">> {session_ip} - {api_key} - blocklist[blocked] search result returned: "
        f"{client_identifier}:{search_identifier}"
    )

    return jsonify(data)


async def get_blocking_search(client_identifier, search_identifier) -> jsonify:
    api_key = request.headers.get("X-API-Key")
    session_ip = await get_ip()

    client_identifier = await sanitization(client_identifier)
    search_identifier = await sanitization(search_identifier)

    logger.info(
        f"<< {session_ip} - {api_key} - blocklist[blocking] search request: {client_identifier}:{search_identifier}"
    )

    if client_identifier and search_identifier:
        client_is_handle = utils.is_handle(client_identifier)
        search_is_handle = utils.is_handle(search_identifier)

        if client_is_handle and search_is_handle:
            result = await database_handler.blocklist_search(client_identifier, search_identifier, switch="blocking")
        else:
            result = None

        block_data = result if result else None

        data = {"data": block_data}
    else:
        if not client_identifier:
            client_identifier = "Missing parameter"
        if not search_identifier:
            search_identifier = "Missing parameter"
        result = "Missing parameter"
        block_data = {"error": result}
        data = {"data": block_data}

    logger.info(
        f">> {session_ip} - {api_key} - blocklist[blocking] search result returned: "
        f"{client_identifier}:{search_identifier}"
    )

    return jsonify(data)


async def fun_facts() -> jsonify:
    global fun_start_time

    api_key = request.headers.get("X-API-Key")
    session_ip = await get_ip()

    logger.info(f"<< Fun facts requested: {session_ip} - {api_key}")

    if not dbs_connected:
        logger.error("Database connection is not live.")

        message = "db not connected"
        error = {"error": message}

        data = {"data": error}

        logger.info(f">> Fun facts result returned: {session_ip} - {api_key}")

        return jsonify(data)

    if database_handler.blocklist_updater_status.is_set():
        logger.info("Updating top blocks in progress.")

        if (
            utils.resolved_blocked_cache.get("resolved_blocked") is None
            or utils.resolved_blockers_cache.get("resolved_blockers") is None
            or utils.blocked_avatar_ids_cache.get("blocked_aid") is None
            or utils.blocker_avatar_ids_cache.get("blocker_aid") is None
        ):
            remaining_time = "not yet determined"

            process_time = database_handler.top_blocks_process_time

            if database_handler.top_blocks_start_time is None:
                start_time = fun_start_time
            else:
                start_time = database_handler.top_blocks_start_time

            if process_time is None:
                remaining_time = "not yet determined"
            else:
                time_elapsed = datetime.now(timezone.utc) - start_time

                if time_elapsed < process_time:
                    # Calculate hours and minutes left
                    time_difference = process_time - time_elapsed
                    seconds_left = time_difference.total_seconds()
                    minutes_left = seconds_left / 60
                    # hours = minutes // 60
                    remaining_seconds = seconds_left % 60

                    if minutes_left > 1:
                        remaining_time = f"{round(minutes_left)} mins {round(remaining_seconds)} seconds"
                    elif seconds_left > 0:
                        remaining_time = f"{round(seconds_left)} seconds"
                else:
                    remaining_time = "just finished"

            timing = {"timeLeft": remaining_time}
            data = {"data": timing}

            logger.info(f">> Fun facts result returned: {session_ip} - {api_key}")

            return jsonify(data)

    resolved_blocked = utils.resolved_blocked_cache.get("resolved_blocked")
    resolved_blockers = utils.resolved_blockers_cache.get("resolved_blockers")

    blocked_aid = utils.blocked_avatar_ids_cache.get("blocked_aid")
    blocker_aid = utils.blocker_avatar_ids_cache.get("blocker_aid")

    data_lists = {
        "blocked": resolved_blocked,
        "blockers": resolved_blockers,
        "blocked_aid": blocked_aid,
        "blockers_aid": blocker_aid,
    }

    # profile_url = "https://av-cdn.bsky.app/img/avatar/plain/{{item.did}}/{{blocked_aid[item.did]}}"

    data = {"data": data_lists, "as of": database_handler.top_blocked_as_of_time}

    logger.info(f">> Fun facts result returned: {session_ip} - {api_key}")

    return jsonify(data)


async def funer_facts() -> jsonify:
    global funer_start_time

    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"<< Funer facts requested: {session_ip} - {api_key}")

    if not dbs_connected:
        logger.error("Database connection is not live.")

        message = "db not connected"
        error = {"error": message}

        data = {"data": error}

        logger.info(f">> Funer facts result returned: {session_ip} - {api_key}")

        return jsonify(data)

    if database_handler.blocklist_24_updater_status.is_set():
        logger.info("Updating top 24 blocks in progress.")

        if (
            utils.resolved_24_blocked_cache.get("resolved_blocked") is None
            or utils.resolved_24blockers_cache.get("resolved_blockers") is None
            or utils.blocked_24_avatar_ids_cache.get("blocked_aid") is None
            or utils.blocker_24_avatar_ids_cache.get("blocker_aid") is None
        ):
            remaining_time = "not yet determined"

            process_time = database_handler.top_24_blocks_process_time

            if database_handler.top_24_blocks_start_time is None:
                start_time = funer_start_time
            else:
                start_time = database_handler.top_24_blocks_start_time

            if process_time is None:
                remaining_time = "not yet determined"
            else:
                time_elapsed = datetime.now(timezone.utc) - start_time

                if time_elapsed < process_time:
                    # Calculate hours and minutes left
                    time_difference = process_time - time_elapsed
                    seconds_left = time_difference.total_seconds()
                    minutes_left = seconds_left / 60
                    # hours = minutes // 60
                    remaining_seconds = seconds_left % 60

                    if minutes_left > 1:
                        remaining_time = f"{round(minutes_left)} mins {round(remaining_seconds)} seconds"
                    elif seconds_left > 0:
                        remaining_time = f"{round(seconds_left)} seconds"
                else:
                    remaining_time = "just finished"

            timing = {"timeLeft": remaining_time}
            data = {"data": timing}

            logger.info(f">> Funer facts result returned: {session_ip} - {api_key}")

            return jsonify(data)

    resolved_blocked_24 = utils.resolved_24_blocked_cache.get("resolved_blocked")
    resolved_blockers_24 = utils.resolved_24blockers_cache.get("resolved_blockers")

    blocked_aid_24 = utils.blocked_24_avatar_ids_cache.get("blocked_aid")
    blocker_aid_24 = utils.blocker_24_avatar_ids_cache.get("blocker_aid")

    data_lists = {
        "blocked24": resolved_blocked_24,
        "blockers24": resolved_blockers_24,
        "blocked_aid": blocked_aid_24,
        "blockers_aid": blocker_aid_24,
    }

    # profile_url = "https://av-cdn.bsky.app/img/avatar/plain/{{item.did}}/{{blocked_aid[item.did]}}"

    data = {"data": data_lists, "as of": database_handler.top_24_blocked_as_of_time}

    logger.info(f">> Funer facts result returned: {session_ip} - {api_key}")

    return jsonify(data)


async def block_stats() -> jsonify:
    global block_stats_app_start_time

    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"<< Requesting block statistics: {session_ip} - {api_key}")

    if not dbs_connected:
        logger.error("Database connection is not live.")

        message = "db not connected"
        error = {"error": message}

        data = {"data": error}

        logger.info(f">> block stats result returned: {session_ip} - {api_key}")

        return jsonify(data)

    if utils.block_stats_status.is_set():
        remaining_time = "not yet determined"

        logger.info("Updating block stats in progress.")

        process_time = utils.block_stats_process_time

        if utils.block_stats_start_time is None:
            start_time = block_stats_app_start_time
        else:
            start_time = utils.block_stats_start_time

        if process_time is None:
            remaining_time = "not yet determined"
        else:
            time_elapsed = datetime.now(timezone.utc) - start_time

            if time_elapsed < process_time:
                # Calculate hours and minutes left
                time_difference = process_time - time_elapsed
                seconds_left = time_difference.total_seconds()
                minutes_left = seconds_left / 60
                # hours = minutes // 60
                remaining_seconds = seconds_left % 60

                if minutes_left > 1:
                    remaining_time = f"{round(minutes_left)} mins {round(remaining_seconds)} seconds"
                elif seconds_left > 0:
                    remaining_time = f"{round(seconds_left)} seconds"
            else:
                remaining_time = "just finished"

        timing = {"timeLeft": remaining_time}
        data = {"data": timing}

        logger.info(f">> block stats result returned: {session_ip} - {api_key}")

        return jsonify(data)

    number_of_total_blocks = utils.number_of_total_blocks_cache.get("total_blocks")
    number_of_unique_users_blocked = utils.number_of_unique_users_blocked_cache.get("unique_blocked")
    number_of_unique_users_blocking = utils.number_of_unique_users_blocking_cache.get("unique_blocker")
    number_blocking_1 = utils.number_block_1_cache.get("block1")
    number_blocking_2_and_100 = utils.number_blocking_2_and_100_cache.get("block2to100")
    number_blocking_101_and_1000 = utils.number_blocking_101_and_1000_cache.get("block101to1000")
    number_blocking_greater_than_1000 = utils.number_blocking_greater_than_1000_cache.get("blockmore1000")
    average_number_of_blocks = utils.average_number_of_blocking_cache.get("averageblocks")
    number_blocked_1 = utils.number_blocked_1_cache.get("blocked1")
    number_blocked_2_and_100 = utils.number_blocked_2_and_100_cache.get("blocked2to100")
    number_blocked_101_and_1000 = utils.number_blocked_101_and_1000_cache.get("blocked101to1000")
    number_blocked_greater_than_1000 = utils.number_blocked_greater_than_1000_cache.get("blockedmore1000")
    average_number_of_blocked = utils.average_number_of_blocked_cache.get("averageblocked")
    total_users = utils.block_stats_total_users_cache.get("total_users")

    percent_users_blocked = (int(number_of_unique_users_blocked) / int(total_users)) * 100
    percent_users_blocking = (int(number_of_unique_users_blocking) / int(total_users)) * 100

    percent_users_blocked = round(percent_users_blocked, 2)
    percent_users_blocking = round(percent_users_blocking, 2)

    percent_number_blocking_1 = round((int(number_blocking_1) / int(number_of_unique_users_blocking) * 100), 2)
    percent_number_blocking_2_and_100 = round(
        (int(number_blocking_2_and_100) / int(number_of_unique_users_blocking) * 100), 2
    )
    percent_number_blocking_101_and_1000 = round(
        (int(number_blocking_101_and_1000) / int(number_of_unique_users_blocking) * 100),
        2,
    )
    percent_number_blocking_greater_than_1000 = round(
        (int(number_blocking_greater_than_1000) / int(number_of_unique_users_blocking) * 100),
        2,
    )

    percent_number_blocked_1 = round((int(number_blocked_1) / int(number_of_unique_users_blocked) * 100), 2)
    percent_number_blocked_2_and_100 = round(
        (int(number_blocked_2_and_100) / int(number_of_unique_users_blocked) * 100), 2
    )
    percent_number_blocked_101_and_1000 = round(
        (int(number_blocked_101_and_1000) / int(number_of_unique_users_blocked) * 100),
        2,
    )
    percent_number_blocked_greater_than_1000 = round(
        (int(number_blocked_greater_than_1000) / int(number_of_unique_users_blocked) * 100),
        2,
    )

    average_number_of_blocks_round = round(float(average_number_of_blocks), 2)
    average_number_of_blocked_round = round(float(average_number_of_blocked), 2)

    number_of_total_blocks_formatted = f"{number_of_total_blocks:,}"
    number_of_unique_users_blocked_formatted = f"{number_of_unique_users_blocked:,}"
    number_of_unique_users_blocking_formatted = f"{number_of_unique_users_blocking:,}"
    total_users_formatted = f"{total_users:,}"
    number_block_1_formatted = f"{number_blocking_1:,}"
    number_blocking_2_and_100_formatted = f"{number_blocking_2_and_100:,}"
    number_blocking_101_and_1000_formatted = f"{number_blocking_101_and_1000:,}"
    number_blocking_greater_than_1000_formatted = f"{number_blocking_greater_than_1000:,}"
    average_number_of_blocks_formatted = f"{average_number_of_blocks_round:,}"
    number_blocked_1_formatted = f"{number_blocked_1:,}"
    number_blocked_2_and_100_formatted = f"{number_blocked_2_and_100:,}"
    number_blocked_101_and_1000_formatted = f"{number_blocked_101_and_1000:,}"
    number_blocked_greater_than_1000_formatted = f"{number_blocked_greater_than_1000:,}"

    stats_data = {
        "numberOfTotalBlocks": {
            "value": number_of_total_blocks_formatted,
            "displayName": "Number of Total Blocks",
        },
        "numberOfUniqueUsersBlocked": {
            "value": number_of_unique_users_blocked_formatted,
            "displayName": "Number of Unique Users Blocked",
        },
        "numberOfUniqueUsersBlocking": {
            "value": number_of_unique_users_blocking_formatted,
            "displayName": "Number of Unique Users Blocking",
        },
        "totalUsers": {
            "value": total_users_formatted,
            "displayName": "Total Users",
        },
        "percentUsersBlocked": {
            "value": percent_users_blocked,
            "displayName": "Percent Users Blocked",
        },
        "percentUsersBlocking": {
            "value": percent_users_blocking,
            "displayName": "Percent Users Blocking",
        },
        "numberBlock1": {
            "value": number_block_1_formatted,
            "displayName": "Number of Users Blocking 1 User",
        },
        "numberBlocking2and100": {
            "value": number_blocking_2_and_100_formatted,
            "displayName": "Number of Users Blocking 2-100 Users",
        },
        "numberBlocking101and1000": {
            "value": number_blocking_101_and_1000_formatted,
            "displayName": "Number of Users Blocking 101-1000 Users",
        },
        "numberBlockingGreaterThan1000": {
            "value": number_blocking_greater_than_1000_formatted,
            "displayName": "Number of Users Blocking More than 1000 Users",
        },
        "percentNumberBlocking1": {
            "value": percent_number_blocking_1,
            "displayName": "Percent of Users Blocking 1 User",
        },
        "percentNumberBlocking2and100": {
            "value": percent_number_blocking_2_and_100,
            "displayName": "Percent of Users Blocking 2-100 Users",
        },
        "percentNumberBlocking101and1000": {
            "value": percent_number_blocking_101_and_1000,
            "displayName": "Percent of Users Blocking 101-1000 Users",
        },
        "percentNumberBlockingGreaterThan1000": {
            "value": percent_number_blocking_greater_than_1000,
            "displayName": "Percent of Users Blocking More than 1000 Users",
        },
        "averageNumberOfBlocks": {
            "value": average_number_of_blocks_formatted,
            "displayName": "Average Number of Blocks",
        },
        "numberBlocked1": {
            "value": number_blocked_1_formatted,
            "displayName": "Number of Users Blocked by 1 User",
        },
        "numberBlocked2and100": {
            "value": number_blocked_2_and_100_formatted,
            "displayName": "Number of Users Blocked by 2-100 Users",
        },
        "numberBlocked101and1000": {
            "value": number_blocked_101_and_1000_formatted,
            "displayName": "Number of Users Blocked by 101-1000 Users",
        },
        "numberBlockedGreaterThan1000": {
            "value": number_blocked_greater_than_1000_formatted,
            "displayName": "Number of Users Blocked by More than 1000 Users",
        },
        "percentNumberBlocked1": {
            "value": percent_number_blocked_1,
            "displayName": "Percent of Users Blocked by 1 User",
        },
        "percentNumberBlocked2and100": {
            "value": percent_number_blocked_2_and_100,
            "displayName": "Percent of Users Blocked by 2-100 Users",
        },
        "percentNumberBlocked101and1000": {
            "value": percent_number_blocked_101_and_1000,
            "displayName": "Percent of Users Blocked by 101-1000 Users",
        },
        "percentNumberBlockedGreaterThan1000": {
            "value": percent_number_blocked_greater_than_1000,
            "displayName": "Percent of Users Blocked by More than 1000 Users",
        },
        "averageNumberOfBlocked": {
            "value": average_number_of_blocked_round,
            "displayName": "Average Number of Users Blocked",
        },
    }

    data = {"data": stats_data, "as of": utils.block_stats_as_of_time}

    logger.info(f">> block stats result returned: {session_ip} - {api_key}")

    return jsonify(data)


async def autocomplete(client_identifier) -> jsonify:
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.debug(f"Autocomplete request: {session_ip} - {api_key}")

    query = client_identifier.lower()

    # Remove the '@' symbol if it exists
    query_without_at = query.lstrip("@")

    logger.debug(f"query: {query}")

    if not query_without_at or "did:" in query_without_at:
        matching_handles = None

        return jsonify({"suggestions": matching_handles})
    else:
        if dbs_connected:
            matching_handles = await database_handler.find_handles(query_without_at)  # Only use db
        else:
            matching_handles = None

        if not matching_handles:
            matching_handles = None

            return jsonify({"suggestions": matching_handles})
        # Add '@' symbol back to the suggestions
        if "@" in query:
            matching_handles_with_at = ["@" + handle for handle in matching_handles]

            return jsonify({"suggestions": matching_handles_with_at})
        else:
            return jsonify({"suggestions": matching_handles})


async def get_internal_status() -> jsonify:
    status = {}
    api_key = request.headers.get("X-API-Key")
    session_ip = await get_ip()

    logger.info(f"<< System status requested: {session_ip} - {api_key}")

    stats_status = "processing" if utils.block_stats_status.is_set() else "waiting" if not dbs_connected else "complete"

    if database_handler.blocklist_updater_status.is_set():
        top_blocked_status = "processing"
    else:
        top_blocked_status = "waiting" if blocklist_failed.is_set() else "complete"

    if database_handler.blocklist_24_updater_status.is_set():
        top_24_blocked_status = "processing"
    else:
        top_24_blocked_status = "waiting" if blocklist_24_failed.is_set() else "complete"

    if database_handler.block_cache_status.is_set():
        block_cache_status = "processing"
    else:
        block_cache_status = "not initialized" if len(database_handler.all_blocks_cache) == 0 else "In memory"

    if dbs_connected:
        for db in dbs_connected:
            resource = db
            status[resource] = "connected"

    now = datetime.now(timezone.utc)
    uptime = now - runtime

    block_stats_last_update = await get_time_since(utils.block_stats_last_update)
    top_block_last_update = await get_time_since(database_handler.last_update_top_block)
    top_24_block_last_update = await get_time_since(database_handler.last_update_top_24_block)
    all_blocks_last_update = await get_time_since(database_handler.all_blocks_last_update)

    status["block stats last update"] = block_stats_last_update
    status["top block last update"] = top_block_last_update
    status["top 24 block last update"] = top_24_block_last_update
    status["block cache last update"] = all_blocks_last_update
    status["current time"] = str(datetime.now(timezone.utc))
    status["clearsky backend version"] = version
    status["uptime"] = str(uptime)
    status["block stats status"] = stats_status
    status["top blocked status"] = top_blocked_status
    status["top 24 blocked status"] = top_24_blocked_status
    status["block cache status"] = block_cache_status
    status["block stats last process time"] = str(utils.block_stats_process_time)
    status["block cache status"] = str(database_handler.all_blocks_process_time)

    logger.info(f">> System status result returned: {session_ip} - {api_key}")

    return jsonify(status)


async def check_api_keys() -> jsonify:
    api_key = request.headers.get("X-API-Key")
    session_ip = await get_ip()

    api_environment = request.args.get("api_environment")
    key_type = request.args.get("key_type")
    key_value = request.args.get("key_value")

    logger.info(f"<< API key check requested: {session_ip} - {api_key}: {api_environment} - {key_type} - {key_value}")

    if not api_key or not api_environment or not key_type or not key_value:
        value = None

        status = {"api_status": "invalid", "api key": value}

        return jsonify(status)

    api_check = await database_handler.check_api_key(api_environment, key_type, key_value)

    api_key_status = "valid" if api_check else "invalid"

    status = {"api_status": api_key_status, "api key": key_value}

    logger.info(
        f">> API key check result returned: {session_ip} - auth key: {api_key} response: "
        f"key: {key_value}- {api_key_status}"
    )

    return jsonify(status)


async def retrieve_dids_per_pds() -> jsonify:
    result = await database_handler.get_dids_per_pds()

    data = {"data": result}

    return jsonify(data)


async def retrieve_subscribe_blocks_blocklist(client_identifier: str, page: int) -> jsonify:
    session_ip = await get_ip()
    try:
        api_key = request.headers.get("X-API-Key")
    except AttributeError:
        api_key = "anonymous"

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {api_key} - blocklist request: {identifier}")

    if identifier:
        did_identifier, handle_identifier = await pre_process_identifier(identifier)
        status = await preprocess_status(did_identifier)

        if did_identifier and handle_identifier and status:
            items_per_page = 100
            offset = (page - 1) * items_per_page

            blocklist, count, pages = await utils.process_subscribe_blocks(
                did_identifier, limit=items_per_page, offset=offset
            )

            formatted_count = f"{count:,}"

            blocklist_data = {
                "blocklist": blocklist,
                "count": formatted_count,
                "pages": pages,
            }
        else:
            blocklist = None
            count = 0

            blocklist_data = {"blocklist": blocklist, "count": count}

        data = {"identity": identifier, "status": status, "data": blocklist_data}
    else:
        identifier = "Missing parameter"
        result = "Missing parameter"
        block_data = {"error": result}
        data = {"data": block_data}

    logger.info(f">> {session_ip} - {api_key} - blocklist result returned: {identifier}")

    return jsonify(data)


async def retrieve_subscribe_blocks_single_blocklist(client_identifier, page) -> jsonify:
    values = await get_var_info()

    count = 0
    pages = 0
    blocklist = None

    api_key = values.get("api_key")
    self_server = values.get("self_server")

    session_ip = await get_ip()
    received_api_key = request.headers.get("X-API-Key")

    identifier = await sanitization(client_identifier)

    logger.info(f"<< {session_ip} - {received_api_key} - blocklist request: {identifier}")

    list_url = []

    if identifier:
        did_identifier, handle_identifier = await pre_process_identifier(identifier)
        status = await preprocess_status(did_identifier)

        if did_identifier and handle_identifier and status:
            items_per_page = 100
            offset = (page - 1) * items_per_page

            headers = {"X-API-Key": f"{api_key}"}
            fetch_api = f"{self_server}/api/v1/auth/get-list/{did_identifier}"

            try:
                async with (
                    aiohttp.ClientSession(headers=headers) as session,
                    session.get(fetch_api) as internal_response,
                ):
                    if internal_response.status == 200:
                        mod_list = await internal_response.json()
                    else:
                        mod_list = "error"
            except Exception as e:
                logger.error(f"Error retrieving mod list from internal API: {e}")
                mod_list = None

            if mod_list is not None:
                if "data" in mod_list and "lists" in mod_list["data"]:
                    for item in mod_list["data"]["lists"]:
                        url = item["url"]

                        list_url.append(url)

                    blocklist, count, pages = await utils.process_subscribe_blocks_single(
                        did_identifier,
                        list_url,
                        limit=items_per_page,
                        offset=offset,
                    )
            else:
                blocklist = None
                count = 0
                pages = 0

            formatted_count = f"{count:,}"

            blocklist_data = {
                "blocklist": blocklist,
                "count": formatted_count,
                "pages": pages,
            }
        else:
            blocklist = None
            count = 0

            blocklist_data = {"blocklist": blocklist, "count": count}

        data = {"identity": identifier, "status": status, "data": blocklist_data}
    else:
        identifier = "Missing parameter"
        result = "Missing parameter"
        block_data = {"error": result}
        data = {"data": block_data}

    logger.info(f">> {session_ip} - {received_api_key} - blocklist result returned: {identifier}")

    return jsonify(data)


async def get_data_storage_path():
    ip, _ = await get_ip_address()

    if ip == "127.0.0.1":
        root_path = os.getcwd()
        path = f"{root_path}/data"
    else:
        path = "/var/data"

    return path


async def filename_validation(filename) -> bool:
    _, extension = os.path.splitext(filename)

    if extension:
        return extension.lower() == ".csv"
    else:
        return False


async def file_content_validation(file_content) -> bool:
    try:
        # Attempt to decode the file content as CSV
        decoded_content = file_content.decode("utf-8")
        csv.reader(decoded_content.splitlines())

        return True
    except csv.Error:
        return False


async def filesize_validation(file) -> bool:
    file_size_bytes = os.path.getsize(file)
    file_size_mb = file_size_bytes / (1024 * 1024)

    return not file_size_mb > upload_limit_mb


async def does_file_exist(file_path) -> bool:
    return bool(os.path.exists(file_path))


async def store_data(
    data, file_name: str, author: str = None, description: str = None, appeal: str = None, list_type: str = None
) -> None:
    base_path = await get_data_storage_path()

    # Define the file paths for the data file and metadata file
    data_file_path = os.path.join(base_path, file_name)
    metadata_file_path = os.path.join(base_path, f"{file_name}.metadata")

    logger.info(f"Data upload for file: {file_name}")

    name_validated = await filename_validation(file_name)
    content_validated = await file_content_validation(data)
    file_exists = await does_file_exist(data_file_path)

    if file_exists:
        raise FileNameExists()

    if name_validated and content_validated and not file_exists:
        # Prepare to read data as a CSV
        data_io = io.StringIO(data.decode("utf-8"))
        reader = csv.reader(data_io)

        # Extract the header row
        header = next(reader)

        # Check if the header is valid
        if not header:
            raise BadRequest("Invalid CSV file format. No header row found.")

        async with aiofiles.open(data_file_path, "w") as file:
            writer = csv.writer(file)
            writer.writerow(header)
            writer.writerows(reader)

        # Write metadata to the metadata file
        async with aiofiles.open(metadata_file_path, "w") as metadata_file:
            await metadata_file.write(f"Author: {author}\n")
            await metadata_file.write(f"Description: {description}\n")
            await metadata_file.write(f"Appeal: {appeal}\n")
            await metadata_file.write(f"List Type: {list_type}\n")

        size_validated = await filesize_validation(data_file_path)

        if not size_validated:
            logger.warning(f"File size exceeded for file: {file_name}")
            await aiofiles.os.remove(data_file_path)
            await aiofiles.os.remove(metadata_file_path)

            raise ExceedsFileSizeLimit()
    else:
        raise BadRequest


async def retrieve_csv_data(file_name=None):
    root_path = await get_data_storage_path()

    if file_name is not None:
        path = f"{root_path}/{file_name}"

        if os.path.exists(path):
            async with aiofiles.open(path, newline="") as file:
                csv_content = await file.read()

            encoded_csv_content = csv_content.encode("utf-8")
            content = io.BytesIO(encoded_csv_content)

            return content
        else:
            raise NotFound
    else:
        raise BadRequest


async def retrieve_csv_files_info(arg) -> jsonify:
    path = await get_data_storage_path()

    files = os.listdir(path)

    files_info = {}

    try:
        if arg == "true":
            for csv_file in files:
                if csv_file.endswith(".csv"):
                    metadata = await read_metadata(csv_file)
                    files_info[csv_file] = metadata

            if not files_info:
                raise NotFound

            data = {"data": files_info}

            return jsonify(data)
    except AttributeError:
        raise BadRequest


async def read_metadata(csv_file):
    base_path = await get_data_storage_path()

    metadata_file_path = os.path.join(base_path, f"{csv_file}.metadata")
    metadata = {}

    if os.path.exists(metadata_file_path):
        async with aiofiles.open(metadata_file_path) as metadata_file:
            async for line in metadata_file:
                key, value = line.strip().split(":", 1)
                metadata[key.strip()] = value.strip()

    return metadata


async def verify_handle(client_identifier) -> jsonify:
    identity = await sanitization(client_identifier)
    is_handle = utils.is_handle(identity)

    if is_handle:
        result = await on_wire.verify_handle(identity)
    else:
        raise BadRequest

    if result:
        response = {"data": {"valid": "true"}, "identity": identity}
    else:
        response = {"data": {"valid": "false"}, "identity": identity}

    return jsonify(response)


async def cursor_recall_status():
    response = None
    db_response = {}

    try:
        cursor = await database_handler.get_cursor_recall()
    except DatabaseConnectionError:
        logger.error("Database connection error")
        return jsonify({"error": "Connection error"}), 503

    if cursor:
        for (
            service,
            current_cursor,
            start_cursor,
            touched,
            interval,
            interval_cursor,
            commit_time,
        ) in cursor:
            db_response[interval] = {
                "service": service,
                "current cursor": current_cursor,
                "start cursor": start_cursor,
                "touched": touched,
                "interval cursor": interval_cursor,
                "commit time": commit_time,
            }

            response = {"data": db_response}

        return response
    else:
        response = {"data": None}

    return response


async def time_behind():
    lag_time_delta = timedelta(seconds=0)

    try:
        cursor_time_behind, override = await database_handler.get_cursor_time()
    except DatabaseConnectionError:
        logger.error("Database connection error")

        return jsonify({"error": "Connection error"}), 503

    try:
        rep_api_key, resource, api_url = await helpers.get_replication_lag_api_key()

        if rep_api_key and resource and api_url:
            headers = {"Authorization": f"Bearer {rep_api_key}"}

            params = {"resource": resource}
            async with httpx.AsyncClient(follow_redirects=True) as client:
                response = await client.get(api_url, headers=headers, params=params)

            if response.status_code == 200:
                replication_lag = response.json()
                if replication_lag:
                    lag_time = replication_lag[0].get("values")[-1].get("value")
                    lag_time_delta = timedelta(milliseconds=lag_time)
            else:
                pass
    except Exception as e:
        logger.error(f"Error fetching replication lag: {e}")
        lag_time_delta = timedelta(seconds=0)

    if override is None or not override:
        if cursor_time_behind:
            current_time = datetime.now(pytz.utc)
            commit_time = cursor_time_behind
            difference = current_time - commit_time + lag_time_delta

            if abs(difference.total_seconds()) < 61:
                logger.info(f"cursor in sync: ~{difference.total_seconds()} seconds")

                response = {"data": {"time behind": "in sync"}}

                return response
            else:
                seconds = int(difference.total_seconds())
                minutes = seconds / 60
                hours = minutes // 60
                remaining_minutes = minutes % 60
                remaining_seconds = seconds % 60

                if hours > 0 and remaining_minutes > 0:
                    if hours == 1:
                        time_behind = f"{int(hours)} hour {int(remaining_minutes)} minutes"
                    else:
                        time_behind = f"{int(hours)} hours {int(remaining_minutes)} minutes"
                elif hours > 0:
                    time_behind = f"{int(hours)} hour" if hours == 1 else f"{int(hours)} hours"
                elif minutes > 0:
                    if minutes >= 1:
                        time_behind = f"{int(minutes)} minutes {int(remaining_seconds)} seconds"
                    else:
                        time_behind = f"{int(seconds)} seconds"
                else:
                    time_behind = "error"

                response = {"data": {"time behind": time_behind}}

                return response
        else:
            response = {"data": "unknown"}

            return response
    else:
        response = {"data": {"time behind": f"{override}"}}

        return response
