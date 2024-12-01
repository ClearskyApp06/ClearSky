# on_wire.py

import asyncio
import json
import urllib.parse

import dns.resolver
import httpx

import database_handler
from config_helper import limiter, logger
from errors import InternalServerError


# ======================================================================================================================
# ============================================= On-Wire requests =======================================================
async def resolve_handle(info):  # Take Handle and get DID
    base_url = "https://api.bsky.app/xrpc/"
    url = urllib.parse.urljoin(base_url, "com.atproto.identity.resolveHandle")
    params = {"handle": info}

    encoded_params = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    full_url = f"{url}?{encoded_params}"
    logger.debug(full_url)

    max_retries = 5
    retry_count = 0

    while retry_count < max_retries:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(full_url)
                response_json = response.json()

                if response.status_code == 200:
                    result = next(iter(response_json.values()))

                    return result
                elif response.status_code == 400:
                    try:
                        error_message = response.json()["error"]
                        message = response.json()["message"]
                        if error_message == "InvalidRequest" and "Unable to resolve handle" in message:
                            logger.warning("Could not find repo: " + str(info))

                            return None
                    except KeyError:
                        logger.error("Error getting response: key error")

                        return None
                else:
                    logger.warning(f"Error resolving {info} response: {response_json}")

                    return None
        except Exception as e:
            retry_count += 1
            logger.error(f"Error occurred while making the API call: {e}")

            return None

    logger.warning("Resolve error for: " + info + " after multiple retries.")

    return None


async def resolve_did(did, did_web_pds=False) -> list | None:  # Take DID and get handle
    base_url = "https://plc.directory/"
    url = f"{base_url}{did}"
    stripped_record = []

    max_retries = 5
    retry_count = 0

    if "did:web" in did:
        logger.info("Resolving did:web")
        short_did = did[len("did:web:") :]
        url = f"https://{urllib.parse.unquote(short_did)}/.well-known/did.json"
    elif "did:tdw" in did:
        logger.info("Resolving did:tdw")
        short_did = did[len("did:tdw:") :]
        url = f"https://{urllib.parse.unquote(short_did)}/.well-known/did.jsonl"
    elif "did:dht" in did:
        logger.info("Resolving did:dht")
        short_did = did[len("did:dht:") :]
        url = f"https://{urllib.parse.unquote(short_did)}/.well-known/did.json"
    elif "did:plc" in did:
        logger.info("Resolving did:plc")
        url = f"{base_url}{did}"

    logger.debug(url)

    while retry_count < max_retries:
        try:
            async with limiter:
                async with httpx.AsyncClient() as client:
                    response = await client.get(url)

                try:
                    response_json = response.json()
                except Exception:
                    logger.warning(f"Error getting JSON response: {url} ")

                    return None

                logger.debug("response: " + str(response_json))

                if response.status_code == 200:
                    if "did:web" in did or "did:dht" in did:
                        response_json = response.json()
                        record = response_json.get("alsoKnownAs", "")
                    elif "did:tdw" in did:
                        response_json = response.text.splitlines()
                        record = [json.loads(entry)["state"]["alsoKnownAs"] for entry in response_json]
                    elif "did:plc" in did:
                        response_json = response.json()
                        record = response_json.get("alsoKnownAs", "")

                    for i in record:
                        stripped_record.append(i.replace("at://", ""))

                    if did_web_pds:
                        logger.info(f"Getting PDS for {did}")
                        endpoint = (
                            response_json["service"][0]["serviceEndpoint"]
                            if "did:web" in did or "did:dht" in did
                            else response_json[-1]["service"][0]["serviceEndpoint"]
                        )
                        logger.info(f"Endpoint retrieved for {did}: {endpoint}")
                        return endpoint

                    if "RateLimit Exceeded" in stripped_record:
                        retry_count += 1
                        sleep_time = 15

                        logger.warning(f"Approaching Rate limit waiting for {sleep_time} seconds")

                        await asyncio.sleep(sleep_time)

                    return stripped_record if stripped_record else None
                elif response.status_code == 429:
                    logger.warning("Too many requests, pausing.")
                    await asyncio.sleep(10)
                elif response.status_code == 404:
                    logger.warning(f"404 not found: {did} | {url}")

                    if response_json:
                        error_message = response_json.get("message", "")
                        logger.debug(error_message)
                    else:
                        error_message = ""

                    if "did not registered" in error_message.lower():
                        await database_handler.deactivate_user(did)

                        return None
                    elif "did not available" in error_message.lower():
                        logger.warning("User not found. Skipping...")

                        return None
                    else:
                        return None
                elif response.status_code == 523:
                    logger.warning("Origin is unreachable")

                    return None
                else:
                    error_message = response_json.get("message", "")
                    logger.debug(error_message)

                    if "did not registered" in error_message.lower():
                        await database_handler.deactivate_user(did)

                        return None
                    elif "did not available" in error_message.lower():
                        logger.warning("User not found. Skipping...")

                        return None
                    else:
                        retry_count += 1
                        logger.warning("Error:" + str(response.status_code))
                        logger.warning("Retrying: " + str(url))
                        await asyncio.sleep(5)
        except httpx.DecodingError as e:
            retry_count += 1
            logger.error(f"Error occurred while parsing JSON response: {e}")

            return None
        except httpx.RequestError as e:
            retry_count += 1
            logger.error(f"Error occurred while making the API call: {e!s} {url}")

            return None
        except httpx.HTTPStatusError as e:
            retry_count += 1
            logger.error(f"Error occurred while parsing JSON response: {e!s} {url}")

            return None
        except Exception as e:
            retry_count += 1
            logger.error(f"An unexpected error occurred: {e!s} {url}")

            return None

    logger.warning("Failed to resolve: " + str(did) + " after multiple retries.")

    return None


async def get_avatar_id(did, aux=False):
    handle = did
    base_url = "https://api.bsky.app/xrpc/"
    collection = "app.bsky.actor.profile"
    rkey = "self"
    url = urllib.parse.urljoin(base_url, "com.atproto.repo.getRecord")
    params = {"repo": handle, "collection": collection, "rkey": rkey}

    encoded_params = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    full_url = f"{url}?{encoded_params}"
    logger.debug(full_url)

    max_retries = 5
    retry_count = 0

    while retry_count < max_retries:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(full_url)
                response_json = response.json()
                logger.debug("response: " + str(response_json))

                if response.status_code == 200:
                    if aux:
                        try:
                            display_value = response_json["value"]["displayName"]
                        except Exception:
                            display_value = None

                        try:
                            description = response_json["value"]["description"]
                        except Exception:
                            description = None

                        return display_value, description
                    avatar_info = response_json.get("value", {}).get("avatar", {})
                    avatar_link = avatar_info.get("ref", {}).get("$link", "")
                    avatar_mimetype = avatar_info.get("mimeType", "")
                    if avatar_link and "jpeg" in avatar_mimetype:
                        return avatar_link
                    elif avatar_link:
                        logger.warning(f"No picture format or incorrect format: {avatar_mimetype}")
                        return avatar_link
                    elif not avatar_link:
                        avatar_cid = avatar_info.get("cid", "")

                        return avatar_cid
                    else:
                        retry_count += 1
                        logger.warning("Error:" + "status code: " + str(response.status_code))
                        logger.error("Could not find avatar ID or picture format")
                        logger.warning("Retrying: " + str(full_url))
                        await asyncio.sleep(10)
                elif response.status_code == 400:
                    logger.warning("User not found. Skipping...")
                    if aux:
                        return None, None

                    return None
                else:
                    error_message = response_json.get("message", "")
                    logger.debug(error_message)

                    break
        except httpx.DecodingError as e:
            retry_count += 1
            logger.error(f"Error occurred while parsing JSON response: {e}")

            return None
        except httpx.RequestError as e:
            retry_count += 1
            logger.error(f"Error occurred while making the API call: {e!s} {full_url}")

            return None
        except httpx.HTTPStatusError as e:
            retry_count += 1
            logger.error(f"Error occurred while parsing JSON response: {e!s} {full_url}")

            return None
        except Exception as e:
            retry_count += 1
            logger.error(f"An unexpected error occurred: {e!s} {full_url}")

            return None

    logger.warning("Failed to resolve: " + str(did) + " after multiple retries.")

    return "Error"


async def resolve_handle_wellknown_atproto(ident):
    url = f"https://{urllib.parse.unquote(ident)}/.well-known/atproto-did"

    max_retries = 5
    retry_count = 0

    while retry_count < max_retries:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                if response.status_code == 200:
                    try:
                        response_json = response.json()
                    except Exception as e:
                        logger.error(f"Error getting json response: {e}")
                        try:
                            response_json = response.text.strip()
                        except Exception as e:
                            logger.error(f"Error getting response from text: {e}")

                            try:
                                response_json = response.content
                            except Exception as e:
                                logger.error(f"Error getting response from content: {e}")

                                raise InternalServerError

                    return response_json
                if response.status_code == 400:
                    logger.debug(f"response 400: {response.json()}")

                    return None

                retry_count += 1
        except Exception as e:
            retry_count += 1
            logger.error(f"Error occurred while making the API call: {e}")

    if retry_count == max_retries:
        logger.warning("Resolve error for: " + ident + " after multiple retries.")

        return None


async def verify_handle(identity) -> bool:
    handle1 = None
    handle2 = None
    handle3 = None

    at_proto_lookup = "_atproto."
    lookup = f"{at_proto_lookup}{identity}"

    at_proto_result = await resolve_handle_wellknown_atproto(identity)
    bsky_result = await resolve_handle(identity)

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        result = resolver.resolve(lookup, "TXT")

        if result:
            result = str(result[0])
            dns_result = result.strip('"')
            dns_result = dns_result.replace("did=", "")
        else:
            dns_result = None
    except Exception as e:
        logger.error(f"Error resolving DNS: {e}")
        dns_result = None

    if any("did:plc" in res for res in [at_proto_result, bsky_result, dns_result]):
        if "bsky.social" in identity:
            return at_proto_result == bsky_result
        else:
            return dns_result == bsky_result or bsky_result == at_proto_result
    elif any("did:web" in res for res in [at_proto_result, bsky_result, dns_result]):
        handle1 = await resolve_did(at_proto_result) if "did:web" in at_proto_result else None
        handle2 = await resolve_did(bsky_result) if "did:web" in bsky_result else None
        handle3 = await resolve_did(dns_result) if "did:web" in dns_result else None
    elif any("did:tdw" in res for res in [at_proto_result, bsky_result, dns_result]):
        handle1 = await resolve_did(at_proto_result) if "did:tdw" in at_proto_result else None
        handle2 = await resolve_did(bsky_result) if "did:tdw" in bsky_result else None
        handle3 = await resolve_did(dns_result) if "did:tdw" in dns_result else None
    elif any("did:dht" in res for res in [at_proto_result, bsky_result, dns_result]):
        handle1 = await resolve_did(at_proto_result) if "did:dht" in at_proto_result else None
        handle2 = await resolve_did(bsky_result) if "did:dht" in bsky_result else None
        handle3 = await resolve_did(dns_result) if "did:dht" in dns_result else None

    handle1 = handle1[0] if handle1 else None
    handle2 = handle2[0] if handle2 else None
    handle3 = handle3[0] if handle3 else None

    if identity in (handle1, handle2, handle3):
        return dns_result == bsky_result or bsky_result == at_proto_result
    else:
        logger.error(
            f"validity case didn't match for {identity} | at_proto: {at_proto_result} | "
            f"bsky: {bsky_result} | dns: {dns_result}"
        )
        return False


async def get_pds(identifier):
    base_url = "https://plc.directory/"
    retry_count = 0
    max_retries = 5

    while retry_count < max_retries:
        full_url = f"{base_url}{identifier}"
        logger.debug(f"full url: {full_url}")

        try:
            async with limiter, httpx.AsyncClient() as client:
                response = await client.get(full_url, timeout=10)  # Set an appropriate timeout value (in seconds)
        except httpx.ReadTimeout:
            logger.warning("Request timed out. Retrying... Retry count: %d", retry_count)
            retry_count += 1
            await asyncio.sleep(5)
            continue
        except httpx.RequestError as e:
            logger.warning("Error during API call: %s", e)
            retry_count += 1
            await asyncio.sleep(5)
            continue

        if response.status_code == 200:
            response_json = response.json()

            try:
                endpoint = response_json.get("service")[0]["serviceEndpoint"]
            except Exception as e:
                endpoint = None
                logger.error(f"Error getting PDS endpoint: {full_url} {e}")

            return endpoint
        elif response.status_code == 429:
            logger.warning("Received 429 Too Many Requests. Retrying after 30 seconds...")
            await asyncio.sleep(30)  # Retry after 60 seconds
        elif response.status_code == 400:
            try:
                error_message = response.json()["error"]
                message = response.json()["message"]
                if error_message == "InvalidRequest" and "Could not find repo" in message:
                    logger.warning("Could not find repo: " + str(identifier))

                    return None
            except KeyError:
                return None
        elif response.status_code == 404:
            logger.warning("404 not found: " + str(identifier))
            return None
        else:
            retry_count += 1
            logger.warning("Error during API call. Status code: %s", response.status_code)
            await asyncio.sleep(5)

            continue
    if retry_count == max_retries:
        logger.warning("Could not get PDS for: " + identifier)

        return None
