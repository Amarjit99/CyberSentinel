"""Install the local OpenSearch event index template."""

import argparse
import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:9200")
    args = parser.parse_args()

    template_path = Path(__file__).parents[1] / "infrastructure" / "opensearch" / "event-template.json"
    body = template_path.read_bytes()
    request = Request(
        f"{args.url.rstrip('/')}/_index_template/cybersentinel-events",
        data=body,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urlopen(request, timeout=10) as response:
            result = json.loads(response.read())
    except (OSError, URLError, json.JSONDecodeError) as exc:
        print(f"OpenSearch template bootstrap failed: {exc}", file=sys.stderr)
        return 1
    if result.get("acknowledged") is not True:
        print(f"OpenSearch rejected template: {result}", file=sys.stderr)
        return 1
    print("OpenSearch event index template installed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
