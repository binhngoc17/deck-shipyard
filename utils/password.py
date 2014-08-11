from hashlib import sha1
from random import random
import re

PASSWORD_POLICY = ('At least 6 characters long')

def hash_password(raw_password):
	if type(raw_password) == unicode:
		raw_password = raw_password.encode('utf8')
	salt = sha1(str(random()) + str(random())).hexdigest()
	hsh = sha1(salt + raw_password).hexdigest()
	return salt + hsh

def check_password(raw_password, hashed_password):
	if type(raw_password) == unicode:
		raw_password = raw_password.encode('utf8')
	salt, hsh = hashed_password[:40], hashed_password[40:]
	return hsh == sha1(salt + raw_password).hexdigest()

def validate_password(password):
	return len(password) >= 6
