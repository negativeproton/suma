# suma
### Simple User Management API

# register and login users


## Disclaimer
This software comes with absolutely no warranty, to the extent permitted by applicable law.  
This code should not be considered secure.


## Description
The program helps programmers to register and login users using a sqlite3 database and pbkdf2_hmac.  
It generates salts using a cryptographically suitable library.  
Input validation is done via whitelisting rules for password and username.  


## Security Note:
It is important to research the current state of password processing/authentication best practices before using the code in the future.  
Is pbkdf2_hmac considered secure?  
Are 200000 repetitions of SHA-256 enough?  
What are the current recommendations?


## Requirements
python3.8+ 


## Installation
No Installation required.  
Import via: 'import db_handler'


## Usage
### Call both methods before the game starts/before the main game loop:
```python
    # Create a database handler instance.
    dh = db_handler.DB_Handler()

    # Login or register new user.
    dh.login_or_register_prompt()
```

### Then in the following processes you can:
```python
    # e.g. access data:
    user_id = str(dh.userid)

    # e.g. save data:
    query = "update user set tie_score = (tie_score + %s) where id = %s;" % (tie_score, user_id)
    dh.cursor.execute(query)
```

### Call this function when the game exits to save the changes:
```python
    dh.finish()
```


## Support
For support please write a comment or open an issue.


## Project status
Development has halted.
