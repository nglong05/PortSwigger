import string

print("".join(c * 10 for c in string.digits + string.ascii_lowercase))
