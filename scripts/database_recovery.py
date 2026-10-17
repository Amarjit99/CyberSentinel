"""Create, restore, and verify database backups for controlled recovery drills."""

import argparse
import sys

from services.persistence.backup import BackupError, create_backup, restore_backup, verify_backup


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)

    backup_parser = subparsers.add_parser("backup", help="Create a database backup")
    backup_parser.add_argument("destination")

    restore_parser = subparsers.add_parser("restore", help="Restore a database backup")
    restore_parser.add_argument("source")
    restore_parser.add_argument("--overwrite", action="store_true")

    verify_parser = subparsers.add_parser("verify", help="Verify a backup file")
    verify_parser.add_argument("source")

    args = parser.parse_args()
    try:
        if args.operation == "backup":
            print(create_backup(args.destination))
        elif args.operation == "restore":
            restore_backup(args.source, allow_overwrite=args.overwrite)
            print("restore completed")
        else:
            if not verify_backup(args.source):
                print("backup verification failed", file=sys.stderr)
                return 1
            print("backup verified")
    except BackupError as exc:
        print(f"database recovery failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
