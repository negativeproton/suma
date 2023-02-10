"""Define a class that works with an existing sqlite3 database file for basic user management.

The database needs the following structure:
CREATE TABLE user ( id int primary key, name text unique not null, key text not null, tie_score int default 0 check (tie_score>=0), salt text);

The columns id, name, key and salt are necessary.
These are required for the user management and should be changed with caution.
The unique constraint for the column 'name' is important.

On the other hand, tiescore is an example for an optional column (from the application, this code could be used on).
Other columns can be added as well.

The database file has to be in the same directory.
Change DB_FILE_NAME (line 19) to equal the file name of the database.
"""

import getpass as gp  # For password field masking against CWE-549.
import hashlib  # To derive a key from a password and a salt via pbkdf2_hmac.
import re  # To check rules for username and password.
import secrets  # For pseudo-random numbers usable in cryptographic contexts.
import sqlite3  # To use a database.
import string
import sys
from sqlite3.dbapi2 import IntegrityError

DB_FILE_NAME: str = 'test.db'

# Strings for input validation of registration and login input (pw and name).
BROKE_NAME_OR_PW_RULES_MESSAGE: str = 'Input not compliant with rules.'
RE_FOR_NAME: str = '^[a-zA-Z]{1,30}$'
RE_FOR_PW: str = '^[a-zA-Z0-9]{9,64}$'


class DB_Handler:
    __instance = None

    def __init__(self) -> None:
        """Singleton class allowing only one instance."""
        if DB_Handler.__instance is not None:
            raise Exception("This class is a singleton!")
        else:
            DB_Handler.__instance = self

        self.con = sqlite3.connect(DB_FILE_NAME)
        self.cursor = self.con.cursor()

    def insert_new_user(self, *args):
        """Create db entry for new users."""
        statement = f"INSERT INTO user VALUES({args[0]},'{args[1]}','{args[2]}',{args[3]},'{args[4]}');"

        self.cursor.execute(statement)
        self.con.commit()

    def finish(self):
        """Make changes of sql query's permanent and close connection."""
        self.con.commit()
        self.con.close()

    def login_or_register_prompt(self):
        """Ask user to log in or register an account."""
        while True:
            user_input = input('Enter either 1 to login or 2 to register a new user: ')
            try:
                if user_input == '1':
                    self.login_user()
                    break
                elif user_input == '2':
                    self.register_new_user()
                    break
                else:
                    raise ValueError

            except ValueError:
                print('Invalid input. Please retry.')

            except EOFError:
                print()
                sys.exit()

            # Prevent attacker to trigger a crash.
            except:
                print('Account not available. Register a new account.')

    def calc_salt(self):
        alphanumeric = string.ascii_letters + string.digits
        salt_length = 32
        salt = ''.join(secrets.choice(alphanumeric) for _ in range(salt_length))
        return salt

    def calc_key_in_hex(self, pw, salt):
        bytes_salt = salt.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), bytes_salt, 100000)
        hex_key = key.hex()
        return hex_key

    def register_new_user(self):
        """Function that lets the user register a new account to use."""
        # SQL insert statement needed.

        random_id = secrets.randbelow(2 * 10 ** 9)

        user_salt = self.calc_salt()

        # Output for Errors that occur, when trying a sql injection.
        sql_injection_message = 'Error! Please be aware of the rules for name and password.'

        unique_user_name = False
        while not unique_user_name:
            # Get user input when asking for credentials to register.

            input_name = input('Enter the account name you want (only letters allowed, up to 30): ')
            if not re.match(RE_FOR_NAME, input_name):
                print(BROKE_NAME_OR_PW_RULES_MESSAGE)
                continue

            pw_info_text = 'Enter the password you want (9-64 chars, only letters and numbers, no special chars): '
            input_pw = gp.getpass(pw_info_text)
            if not re.match(RE_FOR_PW, input_pw):
                print(BROKE_NAME_OR_PW_RULES_MESSAGE)
                continue

            try:
                # Generating key in hex from inputted password.
                user_hex_key = self.calc_key_in_hex(input_pw, user_salt)

                self.insert_new_user(random_id, input_name, user_hex_key, 0, user_salt)

                # If line above worked, then the username is unique.
                unique_user_name = True

            except IntegrityError:
                # Account name already in use. Name column has a unique constraint.
                # Same problem with the secure random chosen ID, if it is already used. No action necessary but retry. 
                print('Error! Please try another user name. ')

            # Avoid giving an attacker information about the database CWE-209.
            except sqlite3.OperationalError:
                print(sql_injection_message)

            except sqlite3.Warning:
                print(sql_injection_message)

            # Prevent an attacker to trigger a crash.
            except:
                print('Please retry. ')

        print(15 * '_')
        print('Registration successful.')
        print('You can login now.')
        print()

        self.login_or_register_prompt()

    def get_salt_from_db(self, account_name):
        """Retrieve user salt and return found string."""
        # Account name already input validated and unique.
        query = "select salt from user where name = '%s';" % account_name
        for row in self.cursor.execute(query):
            return row[0]

    def get_hex_key_from_db(self, account_name):
        """Retrieve user key and return found hex string."""
        # Account name already input validated and unique.
        query = "select key from user where name = '%s';" % account_name
        for row in self.cursor.execute(query):
            return row[0]

    def login_user(self):
        valid_credentials = False

        # Variable to check if there is only one row as answer.
        # Set true, if there is one row.
        # Making it impossible to log in into another account by having duplicated credentials.
        got_one_row = False

        # Get user input when asking for credentials.
        # Validate user input.
        input_name = input('Enter your account name: ')
        if not re.match(RE_FOR_NAME, input_name):
            print(BROKE_NAME_OR_PW_RULES_MESSAGE)
            raise ValueError

        input_pw = gp.getpass()
        if not re.match(RE_FOR_PW, input_pw):
            print(BROKE_NAME_OR_PW_RULES_MESSAGE)
            raise ValueError

        # Retrieving account data from db using the inputted name.
        user_salt = self.get_salt_from_db(input_name)
        user_key = self.get_hex_key_from_db(input_name)

        # Generating key from the inputted password.
        input_hex_key = self.calc_key_in_hex(input_pw, user_salt)

        if input_hex_key != user_key:
            raise ValueError

        query = "SELECT id FROM user where name = '%s' and key = '%s';" % (input_name, input_hex_key)
        for row in self.cursor.execute(query):
            # Deny login to an account if there are duplicates among the credentials.
            if got_one_row is True:
                raise ValueError
            self.userid = row[0]
            valid_credentials = True
            got_one_row = True

        if valid_credentials:
            return self.userid

        raise ValueError
