import time

cache = {}

def get_cached(ip):
    if ip in cache and time.time() - cache[ip]["time"] < 3600:
        return cache[ip]["data"]
    return None

def set_cache(ip, data):
    cache[ip] = {
        "data": data,
        "time": time.time()
    }
