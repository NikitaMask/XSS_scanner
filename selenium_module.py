from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException, NoAlertPresentException

def test_payload_with_selenium(driver, url, payload, input_name): # Добавлен input_name
    try:
        driver.get(url)
        try:
            input_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.NAME, input_name)) # Используем переданное имя
            )
            input_field.clear()
            input_field.send_keys(payload)
            input_field.submit()
        except NoSuchElementException:
            print(f"Selenium: Элемент с именем {input_name} не найден")
            return False

        try:
            WebDriverWait(driver, 10).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            print(f"[DOM XSS] Обнаружено alert окно: {alert_text} на URL: {url} с payload: {payload}")
            alert.accept()
            return True
        except TimeoutException:
            print(f"Selenium: Timeout при ожидании alert")
            return False
        except NoAlertPresentException: # Добавлена обработка NoAlertPresentException
            print(f"Selenium: Alert не найден")
            return False

    except WebDriverException as e:
        print(f"Selenium Error: {e}")
        return False
    return False

def init_driver():
    """Инициализирует драйвер Chrome для Selenium"""
    try:
        driver = webdriver.Chrome()
        return driver
    except Exception as e:
        print(f"[Selenium Error] Не удалось инициализировать драйвер: {e}")
        return None

def driver_quit(driver):
    """Закрывает экземпляр веб-драйвера Selenium."""
    driver.quit()