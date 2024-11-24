# Clearsky

This Application provides information from Bluesky using ATProto.

## Table of contents

- [Developer environment setup](#setup)
- [Development processes](#development)
- [Deployment](#deployment)

## Setup

Optional tooling to ease life:

* pyenv - https://github.com/pyenv/pyenv
* direnv - https://direnv.net/#getting-started
* just - https://just.systems/man/en/packages.html
* Docker compose - https://docs.docker.com/compose/

If you've installed all of the above tooling, get started with:

```
just first-time-setup
```

If you're setting things up by hand or without the above tooling:

1. You need to set up and activate a virtual environment running Python 3.12.5
    * If that virtual environment is not at `./venv/` then you need to create a symbolic link to it with that name.
2. You need to get the contents of .env.local into your shell environment
3. Run: `pip install -r requirements.txt -r requirements-dev.txt`
4. Run: `pre-commit install`

## Development

### To add a new dependency:

* Add the dependency to `requirements.in` or `requirements-dev.in` as appropriate.
* Run `just pip-update`

## Deployment
