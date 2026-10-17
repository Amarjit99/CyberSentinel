"""Create and restore OpenSearch snapshots with explicit safety checks."""

import argparse
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def request_json(base_url: str, path: str, method: str = "GET", payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        f"{base_url.rstrip('/')}/{path.lstrip('/')}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"OpenSearch request failed for {path}: {exc}") from exc


def register_repository(base_url: str, repository: str, location: str) -> dict:
    return request_json(
        base_url,
        f"_snapshot/{repository}",
        method="PUT",
        payload={"type": "fs", "settings": {"location": location, "compress": True}},
    )


def create_snapshot(base_url: str, repository: str, snapshot: str) -> dict:
    return request_json(base_url, f"_snapshot/{repository}/{snapshot}?wait_for_completion=true", "PUT")


def restore_snapshot(
    base_url: str,
    repository: str,
    snapshot: str,
    *,
    allow_destructive_restore: bool,
) -> dict:
    if not allow_destructive_restore:
        raise ValueError(
            "Restore replaces indexed data; pass --allow-destructive-restore explicitly"
        )
    return request_json(
        base_url,
        f"_snapshot/{repository}/{snapshot}/_restore?wait_for_completion=true",
        method="POST",
        payload={"include_global_state": False, "include_aliases": True},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("register", "create", "restore"))
    parser.add_argument("--repository", default=os.getenv("OPENSEARCH_SNAPSHOT_REPOSITORY", "cybersentinel"))
    parser.add_argument("--location", default=os.getenv("OPENSEARCH_SNAPSHOT_LOCATION"))
    parser.add_argument("--snapshot", default=os.getenv("OPENSEARCH_SNAPSHOT_NAME"))
    parser.add_argument("--url", default=os.getenv("OPENSEARCH_URL", "http://127.0.0.1:9200"))
    parser.add_argument("--allow-destructive-restore", action="store_true")
    args = parser.parse_args()

    if args.action == "register":
        if not args.location:
            parser.error("--location or OPENSEARCH_SNAPSHOT_LOCATION is required")
        result = register_repository(args.url, args.repository, args.location)
    else:
        if not args.snapshot:
            parser.error("--snapshot or OPENSEARCH_SNAPSHOT_NAME is required")
        result = (
            create_snapshot(args.url, args.repository, args.snapshot)
            if args.action == "create"
            else restore_snapshot(
                args.url,
                args.repository,
                args.snapshot,
                allow_destructive_restore=args.allow_destructive_restore,
            )
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
