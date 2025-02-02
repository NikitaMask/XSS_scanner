from bs4 import BeautifulSoup


def parse_html(html):
    try:
        soup = BeautifulSoup(html, 'html.parser')
        return soup
    except Exception as e:
        print(f"[Parsing Error] {e}")
        return None


def find_forms(soup):
    if soup:
        return soup.find_all('form')
    return []


def find_inputs(form):
    if form:
        return form.find_all(['input', 'textarea', 'select'])
    return []