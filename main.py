from urllib.parse import urljoin
import re
import tkinter as tk
from .request_module import send_request
from .parsing_module import parse_html, find_forms, find_inputs
from .analysis_module import XSSAnalyzer
from .selenium_module import test_payload_with_selenium, init_driver, driver_quit

gui_text_area = None
def print_vulnerability(vulnerability_type, url, payload, request_url, status_code=None):
    """Выводит информацию об уязвимости"""
    message = f"[{vulnerability_type}] Возможная XSS уязвимость найдена на {url} при отправке: {payload}\n"
    message += f"URL запроса: {request_url}\n"
    if status_code:
        message += f"Код ответа: {status_code}\n"
    if gui_text_area:  # проверяем, инициализирована ли текстовая область GUI
        gui_text_area.after(lambda: gui_text_area.insert(tk.END, message))
    else:
        print(message, end="")

def scan_xss_vulnerabilities(url):
    """Основная функция сканирования XSS уязвимостей."""

    response = send_request('GET', url)     #отправляем GET запрос на целевой URL
    if not response:                        #проверка, получен ли ответ
        return

    soup = parse_html(response.text)        #парсим HTML ответ
    if not soup:
        return

    forms = find_forms(soup)                #находим все формы на странице
    print(f"Найдено форм: {len(forms)}")    #получаем все XSS пейлоады

    analyzer = XSSAnalyzer()                #создаем экземпляр класса XSSAnalyzer
    payloads = analyzer.get_all_payloads()

    driver = init_driver()                  #инициализируем драйвер Selenium для DOM XSS
    if driver is None:
        print("Не удалось инициализировать драйвер Selenium. DOM XSS тесты будут пропущены.")

    for form in forms:
        action = form.get('action', '')                 #получаем атрибут action формы
        method = form.get('method', 'GET').upper()      #получаем метод формы GET/POST
        absolute_action_url = urljoin(url, action)      #формируем абсолютный URL для отправки запроса

        inputs = find_inputs(form)          #находим все поля ввода в форме
        print(f'Найдено полей ввода: {len(inputs)}')

        for input_tag in inputs:
            name = input_tag.get('name', 'Без имени')
            print(f"Проверка поля: {name} в форме {method} {absolute_action_url}")

            for payload in payloads:
                test_url = absolute_action_url
                data = {name: payload} if method == 'POST' else {name: payload} if method == "GET" else None

                test_response = send_request(method, test_url, data=data)       #отправляем запрос с пейлоадом
                if test_response:
                    #проверка на отраженные XSS
                    report = analyzer.analyze_response(payload, test_response.text, test_response.url, test_response.status_code)
                    if report:
                        print_vulnerability(report["type"], url, payload, report['request_url'], report['status_code'])
                    print(f"[Reflected XSS] Возможная XSS уязвимость найдена на {test_url} с payload: {payload}")

                    #проверка на DOM XSS
                    if driver:      #если драйвер Selenium инициализирован
                        if test_payload_with_selenium(driver, test_url, payload, name):     #тестируем на DOM XSS
                            pass

    if driver:
        driver_quit(driver)     #закрываем драйвер Selenium

    # Поиск уязвимостей в URL параметрах
    query_params = re.findall(r"\?([^#]*)", url)      #ищем параметры в URL
    if query_params:
        params_string = query_params[0]
        params = params_string.split('&')
        print(f"Обнаружены параметры URL: {params}")

        #обработка параметров URL, аналогично обработке форм
        for param in params:
            if "=" in param:
                param_name = param.split("=")[0]
                print(f"Проверка параметра URL: {param_name}")
                for payload in payloads:
                    test_url = url.split("?")[0] + f"?{param_name}={payload}"
                    print(f"Тестовый URL: {test_url}")
                    test_response = send_request("GET", test_url)
                    if test_response:
                        report = analyzer.analyze_response(payload, test_response.text, test_response.url, test_response.status_code)
                        if report:
                            print_vulnerability("Reflected XSS в параметре URL", url, payload, report['request_url'], report['status_code'])
                        if driver:
                            if test_payload_with_selenium(driver, test_url, payload, param_name):
                                print_vulnerability("DOM XSS в параметре URL", url, payload, test_response.url)
            else:
                print(f"Параметр URL без значения: {param}. Пропускаем.")
    else:
        print("Параметры URL не найдены.")


if __name__ == "__main__":
    url = "http://localhost:8888/page1/xss_vulnerable.php?attribute=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E"
    #url = "http://localhost:8888/page1/test.php"
    scan_xss_vulnerabilities(url)
    url_with_params = "http://localhost:8888/page1/xss_vulnerable.php?attribute=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS%27%29%3E"
    scan_xss_vulnerabilities(url_with_params)