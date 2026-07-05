"""Kairon administrative CLI."""
from __future__ import annotations

import argparse
import getpass
import sys

from app.core.database import SessionLocal
from app.models.user import User
from app.services.auth_utils import hash_password


def cmd_create_admin(args: argparse.Namespace) -> None:
    from app.core.database import init_db
    init_db()
    db = SessionLocal()
    try:
        username = args.username or input("Username: ")
        password = args.password or getpass.getpass("Password: ")
        if len(password) < 12:
            print("Password must be at least 12 characters")
            sys.exit(1)
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            print(f"User {username} already exists")
            sys.exit(1)
        user = User(
            username=username,
            email=args.email or None,
            display_name=username,
            password_hash=hash_password(password),
            is_admin=True,
            is_active=True,
        )
        db.add(user)
        db.commit()
        print(f"Admin user {username} created")
    finally:
        db.close()


def cmd_list_users(args: argparse.Namespace) -> None:
    from app.core.database import init_db
    init_db()
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.username).all()
        if not users:
            print("No users found")
            return
        for u in users:
            admin_flag = " *" if u.is_admin else ""
            active_flag = "" if u.is_active else " [disabled]"
            print(f"  {u.username}{admin_flag}{active_flag}  email={u.email or '-'}  id={u.id}")
    finally:
        db.close()


def cmd_reset_password(args: argparse.Namespace) -> None:
    from app.core.database import init_db
    init_db()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == args.username).first()
        if not user:
            print(f"User {args.username} not found")
            sys.exit(1)
        password = args.password or getpass.getpass("New password: ")
        if len(password) < 12:
            print("Password must be at least 12 characters")
            sys.exit(1)
        user.password_hash = hash_password(password)
        db.commit()
        print(f"Password reset for {args.username}")
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Kairon administrative CLI")
    sub = parser.add_subparsers(dest="command")

    create_admin_parser = sub.add_parser("create-admin", help="Create an admin user")
    create_admin_parser.add_argument("--username", help="Admin username")
    create_admin_parser.add_argument("--password", help="Admin password")
    create_admin_parser.add_argument("--email", help="Admin email")

    sub.add_parser("list-users", help="List all users")

    reset_parser = sub.add_parser("reset-password", help="Reset a user's password")
    reset_parser.add_argument("--username", required=True, help="Target username")
    reset_parser.add_argument("--password", help="New password")

    args = parser.parse_args()

    if args.command == "create-admin":
        cmd_create_admin(args)
    elif args.command == "list-users":
        cmd_list_users(args)
    elif args.command == "reset-password":
        cmd_reset_password(args)
    else:
        parser.print_help()
