import tkinter as tk
from tkinter import scrolledtext, messagebox
from urllib.parse import urljoin
import re
import threading
from . import request_module, parsing_module, analysis_module, selenium_module

def scan_xss():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Ошибка", "Пожалуйста, введите URL.")
        return

    result_text.delete("1.0", tk.END)  # Очищаем текстовое поле

    def print_to_text(text):
        result_text.insert(tk.END, text + "\n")
        result_text.see(tk.END) # Автоматическая прокрутка

    print_to_text(f"Сканирование URL: {url}")

    def scan_in_thread():
        if not request_module.is_server_reachable("localhost", 8888):
            print_to_text("Сервер недоступен. Убедитесь, что он запущен.")
            return

        response = request_module.send_request('GET', url)
        if not response:
            print_to_text("Ошибка при запросе URL.")
            return

        soup = parsing_module.parse_html(response.text)
        if not soup:
            print_to_text("Ошибка при парсинге HTML.")
            return

        forms = parsing_module.find_forms(soup)
        print_to_text(f"Найдено форм: {len(forms)}")

        analyzer = analysis_module.XSSAnalyzer()
        payloads = analyzer.get_all_payloads()

        driver = selenium_module.init_driver()
        if driver is None:
            print_to_text("Не удалось инициализировать драйвер Selenium. DOM XSS тесты будут пропущены.")

        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            absolute_action_url = urljoin(url, action)

            inputs = parsing_module.find_inputs(form)
            print_to_text(f'Найдено полей ввода: {len(inputs)}')

            for input_tag in inputs:
                name = input_tag.get('name', 'Без имени')
                print_to_text(f"Проверка поля: {name} в форме {method} {absolute_action_url}")

                for payload in payloads:
                    test_url = absolute_action_url
                    data = {name: payload} if method == 'POST' else None

                    test_response = request_module.send_request(method, test_url, data=data)
                    if test_response:
                        report = analyzer.analyze_response(payload, test_response.text, test_response.url, test_response.status_code)
                        if report:
                            print_to_text(f"[Reflected XSS] Возможная XSS уязвимость: {url}, Payload: {payload}, URL запроса: {test_response.url}, Код: {test_response.status_code}")
                        if driver:
                            if selenium_module.test_payload_with_selenium(driver, test_url, payload, name):
                                print_to_text(f"[DOM XSS] Уязвимость подтверждена Selenium: {test_url}, Payload: {payload}")

        if driver:
            selenium_module.driver_quit(driver)

        query_params = re.findall(r"\?([^#]*)", url)
        if query_params:
            params_string = query_params[0]
            params = params_string.split('&')
            print_to_text(f"Обнаружены параметры URL: {params}")

            for param in params:
                if "=" in param:
                    param_name = param.split("=")[0]
                    print_to_text(f"Проверка параметра URL: {param_name}")
                    for payload in payloads:
                        test_url = url.split("?")[0] + f"?{param_name}={payload}"
                        print_to_text(f"Тестовый URL: {test_url}")
                        test_response = request_module.send_request("GET", test_url)
                        if test_response:
                            report = analyzer.analyze_response(payload, test_response.text, test_response.url, test_response.status_code)
                            if report:
                                print_to_text(f"[Reflected XSS в параметре URL] Возможная XSS уязвимость: {url}, Payload: {payload}, URL запроса: {test_response.url}, Код: {test_response.status_code}")
                            if driver:
                                if selenium_module.test_payload_with_selenium(driver, test_url, payload, param_name):
                                    print_to_text(f"[DOM XSS в параметре URL] Уязвимость подтверждена Selenium: {test_url}, Payload: {payload}")
                else:
                    print_to_text(f"Параметр URL без значения: {param}. Пропускаем.")
        else:
            print_to_text("Параметры URL не найдены.")

    thread = threading.Thread(target=scan_in_thread)
    thread.start()

root = tk.Tk()
root.title("XSS Scanner")

url_label = tk.Label(root, text="URL:")
url_label.grid(row=0, column=0, padx=5, pady=5)

url_entry = tk.Entry(root, width=50)
url_entry.grid(row=0, column=1, padx=5, pady=5)

scan_button = tk.Button(root, text="Сканировать", command=scan_xss)
scan_button.grid(row=1, column=0, columnspan=2, pady=10)

result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20)
result_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()