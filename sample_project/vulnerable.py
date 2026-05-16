import os
import subprocess

password = "super-secret-password"


def run(user_value):
    eval(user_value)
    subprocess.call("echo " + user_value, shell=True)
    os.system("dir " + user_value)
