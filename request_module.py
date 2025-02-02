import requests
from requests.exceptions import ConnectionError, Timeout, RequestException
import socket

def is_server_reachable(host, port):
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except OSError:
        return False

def send_request(method, url, data=None, timeout=10, allow_redirects=False):
    """Отправляет HTTP-запрос заданным методом"""
    try:
        response = requests.request(method, url, data=data, timeout=timeout, allow_redirects=allow_redirects)
        response.raise_for_status()  # вызывает исключение для кодов ошибок 4xx и 5xx
        return response
    except ConnectionError as e:
        print(f"[Request Error] Ошибка соединения: {e}")
        return None
    except Timeout as e:
        print(f"[Request Error] Превышено время ожидания: {e}")
        return None
    except RequestException as e:
        print(f"[Request Error] Произошла ошибка запроса: {e}")
        return None
    except Exception as e:  # Обработка других возможных исключений
        print(f"[Request Error] Непредвиденная ошибка: {e}")
        return None