"""Admin helper for when you are locked out. Run from the project folder:

    python backend/manage.py list                      show all users
    python backend/manage.py reset-password you@example.com   set a new password for a user (asks you for it)
"""
import getpass
import sys

from services import users


def main(argv):
    if argv == ["list"]:
        for u in users.list_all():
            print(u["id"], u["email"], u["role"], u["status"])
        return 0
    if len(argv) == 2 and argv[0] == "reset-password":
        first, again = getpass.getpass("New password (10-128 characters, not your email, not too simple): "), getpass.getpass("Repeat it: ")
        if first != again:
            print("The two passwords do not match.")
            return 1
        try:
            users.force_set_password(argv[1], first)   # applies the password policy itself
        except (ValueError, LookupError) as e:
            print("Error:", e)
            return 1
        print("Password changed. You can sign in now.")
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
