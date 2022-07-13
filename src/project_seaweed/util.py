"""helper functions for the program"""
import sys
import requests
import logging

def is_reachable(url:str)->bool:
    """Returns True only if URL is alive and responds with 200 OK"""
    try:
        response=requests.head()
        if response.status_code==200:
            return True
        else:
            return False
    except BaseException:
        sys.exit("URL is not reachable. Exiting program...")