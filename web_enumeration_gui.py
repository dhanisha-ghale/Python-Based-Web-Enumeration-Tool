import requests
import threading
from abc import ABC, abstractmethod
from queue import Queue
from urllib.parse import urljoin, urlparse, urlunparse
import socket
import json
import logging
import re
from tkinter import Tk, Label, Button, Entry, Text, END, Scrollbar, VERTICAL, messagebox
from tkinter.ttk import Separator, Style
from tkinter.scrolledtext import ScrolledText

# Set up logging
logging.basicConfig(
    filename='web_enumeration.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Helper Functions
def is_valid_domain(domain):
    pattern = r"^(?!://)([a-zA-Z0-9-_]+(?:\.[a-zA-Z0-9-_]+)+)$"
    return re.match(pattern, domain) is not None

def is_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def normalize_url(url):
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))


class WebEnumeration(ABC):
    def __init__(self, target):
        self._target = target

    @abstractmethod
    def enumerate(self):
        pass


class SubdomainEnumerator(WebEnumeration):
    def __init__(self, target, subdomains):
        super().__init__(target)
        self.subdomains = subdomains
        self.found_subdomains = []
        self.lock = threading.Lock()

    def check_subdomain(self, subdomain):
        for protocol in ['http', 'https']:
            url = f"{protocol}://{subdomain}.{self._target}"
            try:
                response = requests.get(url, timeout=2, headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    with self.lock:
                        self.found_subdomains.append(url)
                        logging.info(f"Found subdomain: {url}")
            except requests.RequestException:
                pass

    def enumerate(self):
        threads = []
        for subdomain in self.subdomains:
            thread = threading.Thread(target=self.check_subdomain, args=(subdomain,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        return self.found_subdomains


class PortScanner(WebEnumeration):
    def __init__(self, target, ports):
        super().__init__(target)
        self.ports = ports
        self.open_ports = []

    def scan_port(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((self._target, port))
            if result == 0:
                self.open_ports.append(port)
                logging.info(f"Open port: {port}")

    def enumerate(self):
        threads = []
        for port in self.ports:
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        return self.open_ports


class WebCrawler(WebEnumeration):
    def __init__(self, target):
        super().__init__(target)
        self.visited = set()
        self.queue = Queue()

    def extract_links(self, html, base_url):
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                links.add(normalize_url(full_url))
        return links

    def enumerate(self):
        self.queue.put(self._target)
        self.visited.add(normalize_url(self._target))

        while not self.queue.empty():
            current_url = self.queue.get()
            logging.info(f"Visiting URL: {current_url}")
            try:
                response = requests.get(current_url, timeout=2, headers={'User-Agent': 'Mozilla/5.0'})
                for link in self.extract_links(response.text, current_url):
                    if link not in self.visited:
                        self.visited.add(link)
                        self.queue.put(link)
            except requests.RequestException:
                pass
        return self.visited


class DirectoryEnumerator(WebEnumeration):
    def __init__(self, target, wordlist):
        super().__init__(target)
        self.wordlist = wordlist
        self.found_directories = []

    def check_directory(self, directory):
        for protocol in ['http', 'https']:
            url = f"{protocol}://{self._target}/{directory}/"
            try:
                response = requests.get(url, timeout=2, headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    self.found_directories.append(url)
                    logging.info(f"Found directory: {url}")
            except requests.RequestException:
                pass

    def enumerate(self):
        threads = []
        for directory in self.wordlist:
            thread = threading.Thread(target=self.check_directory, args=(directory,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        return self.found_directories


class WebEnumerationToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Web Enumeration Tool")
        self.center_window(550, 600)
        self.root.configure(bg="#e9f5ff")

        style = Style()
        style.configure("TButton", padding=5, font=("Times New Roman", 10))

        Label(root, text="Web Enumeration Tool", font=("Times New Roman", 18, "bold"), bg="#e9f5ff", fg="#0056b3").grid(row=0, columnspan=2, pady=15)

        # Labels and Entry for Target Domain
        Label(root, text="Target Domain:", font=("Times New Roman", 12), bg="#e9f5ff").grid(row=1, column=0, pady=10, padx=10, sticky="w")
        self.target_entry = Entry(root, width=50)
        self.target_entry.grid(row=1, column=1, padx=10)

        # Buttons
        Button(root, text="Run Enumeration", command=self.run_enumeration, bg="#007BFF", fg="white", width=20).grid(row=2, column=0, pady=10)
        Button(root, text="Show Manual", command=self.show_manual, bg="#17A2B8", fg="white", width=20).grid(row=2, column=1, pady=10, sticky="w")

        # Separator
        Separator(root, orient="horizontal").grid(row=3, columnspan=2, sticky="ew", pady=10)

        # Result Output
        Label(root, text="Results:", font=("Times New Roman", 12), bg="#e9f5ff").grid(row=4, column=0, padx=10, pady=5, sticky="w")
        self.result_output = ScrolledText(root, width=80, height=25, bg="#ffffff", font=("Times New Roman", 10))
        self.result_output.grid(row=5, columnspan=2, pady=5, padx=10)

    def center_window(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x_coordinate = (screen_width // 2) - (width // 2)
        y_coordinate = (screen_height // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x_coordinate}+{y_coordinate}")

    def log_message(self, message):
        self.result_output.insert(END, message + '\n')
        self.result_output.see(END)

    def run_enumeration(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target domain.")
            return

        if not is_valid_domain(target) or not is_resolvable(target):
            messagebox.showerror("Error", "Invalid or unresolvable domain. Please try again.")
            return

        self.result_output.delete(1.0, END)
        self.log_message("Starting Web Enumeration Tool...")

        # Subdomain Enumeration
        subdomains = ["www", "test", "dev", "staging"]
        subdomain_enum = SubdomainEnumerator(target, subdomains)
        self.log_message("Enumerating subdomains...")
        found_subdomains = subdomain_enum.enumerate()
        self.log_message(f"Found subdomains: {found_subdomains}")

        # Port Scanning
        ports = [80, 443, 8080, 22]
        port_scanner = PortScanner(target, ports)
        self.log_message("Scanning ports...")
        open_ports = port_scanner.enumerate()
        self.log_message(f"Open ports: {open_ports}")

        # Web Crawling
        crawler = WebCrawler(f"http://{target}")
        self.log_message("Starting web crawling...")
        crawled_urls = crawler.enumerate()
        self.log_message(f"Crawled URLs: {list(crawled_urls)}")

        # Directory Enumeration
        wordlist = ["admin", "backup", "hidden", "config", "uploads"]
        directory_enum = DirectoryEnumerator(target, wordlist)
        self.log_message("Enumerating directories...")
        found_directories = directory_enum.enumerate()
        self.log_message(f"Found directories: {found_directories}")

        # Save Results
        results = {
            "subdomains": found_subdomains,
            "open_ports": open_ports,
            "crawled_urls": list(crawled_urls),
            "found_directories": found_directories
        }
        with open("web_enumeration_results.json", "w") as f:
            json.dump(results, f, indent=4)

        self.log_message("Results saved to web_enumeration_results.json")

    def show_manual(self):
        manual_text = (
            "Web Enumeration Tool Manual:\n"
            "-----------------------------\n"
            "This tool performs the following tasks:\n"
            "1. Subdomain Enumeration\n"
            "2. Port Scanning\n"
            "3. Web Crawling\n"
            "4. Directory Enumeration\n"
            "\nHow It Works:\n"
            "- Enter a valid target domain (e.g., example.com).\n"
            "- Click 'Run Enumeration' to start.\n"
            "- Results are displayed in the output area and saved to JSON.\n"
        )
        messagebox.showinfo("Manual", manual_text)


if __name__ == "__main__":
    root = Tk()
    app = WebEnumerationToolGUI(root)
    root.mainloop()