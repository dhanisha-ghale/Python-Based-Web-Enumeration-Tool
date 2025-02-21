import requests
import threading
from abc import ABC, abstractmethod
from queue import Queue
from urllib.parse import urljoin, urlparse, urlunparse
import socket
import json
import logging
import re 

# Set up logging
logging.basicConfig(
    filename='web_enumeration.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Helper Functions
def is_valid_domain(domain):
    """Validate the target domain name."""
    pattern = r"^(?!:\/\/)([a-zA-Z0-9-_]+(?:\.[a-zA-Z0-9-_]+)+)$"
    return re.match(pattern, domain) is not None

def is_resolvable(domain):
    """Check if the domain can be resolved to an IP address."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def normalize_url(url):
    """Normalize URLs to avoid duplicates in crawling."""
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

# Abstract Base Class
class WebEnumeration(ABC):
    def __init__(self, target):
        self._target = target

    @abstractmethod
    def enumerate(self):
        pass

    def get_target(self):
        return self._target

# Subdomain Enumerator
class SubdomainEnumerator(WebEnumeration):
    def __init__(self, target, subdomains):
        super().__init__(target)
        self.subdomains = subdomains
        self.found_subdomains = []
        self.lock = threading.Lock()  # Thread-safe access to shared resources

    def check_subdomain(self, subdomain):
        """Check if a subdomain is active."""
        for protocol in ['http', 'https']:
            url = f"{protocol}://{subdomain}.{self._target}"
            try:
                response = requests.get(url, timeout=2, headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    with self.lock:  # Ensure thread-safe access
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

# Port Scanner
class PortScanner(WebEnumeration):
    def __init__(self, target, ports):
        super().__init__(target)
        self.ports = ports
        self.open_ports = []

    def scan_port(self, port):
        """Check if a port is open."""
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

# Web Crawler
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
            print(f"Visiting: {current_url}")
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

# Directory Enumerator
class DirectoryEnumerator(WebEnumeration):
    def __init__(self, target, wordlist):
        super().__init__(target)
        self.wordlist = wordlist
        self.found_directories = []

    def check_directory(self, directory):
        """Check if a directory exists."""
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

# Orchestrator
class WebEnumerationTool:
    def __init__(self, target):
        self.target = target

    def run(self):
        if not is_valid_domain(self.target) or not is_resolvable(self.target):
            print("Invalid domain or unable to resolve target domain. Please check the input.")
            return

        print("Starting Web Enumeration Tool")

        # Subdomain Enumeration
        subdomains = ["www", "test", "dev", "staging"]
        subdomain_enum = SubdomainEnumerator(self.target, subdomains)
        print("Enumerating subdomains...")
        found_subdomains = subdomain_enum.enumerate()
        print("Found subdomains:", found_subdomains)

        # Port Scanning
        ports = [80, 443, 8080, 22]
        port_scanner = PortScanner(self.target, ports)
        print("Scanning ports...")
        open_ports = port_scanner.enumerate()
        print("Open ports:", open_ports)

        # Web Crawling
        print("Starting web crawling...")
        crawler = WebCrawler(f"http://{self.target}")
        crawled_urls = crawler.enumerate()
        print("Crawled URLs:", crawled_urls)

        # Directory Enumeration
        wordlist = ["admin", "backup", "hidden", "config", "uploads"]
        directory_enum = DirectoryEnumerator(self.target, wordlist)
        print("Enumerating directories...")
        found_directories = directory_enum.enumerate()
        print("Found directories:", found_directories)

        # Save results to JSON
        results = {
            "subdomains": found_subdomains,
            "open_ports": open_ports,
            "crawled_urls": list(crawled_urls),
            "found_directories": found_directories
        }
        with open("web_enumeration_results.json", "w") as f:
            json.dump(results, f, indent=4)
        print("Results saved to web_enumeration_results.json")

    def show_manual(self):
        print("""
        Web Enumeration Tool Manual:
        -----------------------------
        This tool performs the following tasks:

        1. Subdomain Enumeration:
           - Checks for active subdomains from a predefined list.
           - Uses HTTP and HTTPS protocols to validate each subdomain.

        2. Port Scanning:
           - Scans common ports on the target domain (e.g., 80, 443, 8080, 22).
           - Identifies open ports using TCP connect scans.

        3. Web Crawling:
           - Traverses the target domain starting from the base URL.
           - Extracts all reachable links within the same domain.

        4. Directory Enumeration:
           - Tests for common hidden directories on the target domain.
           - Uses a predefined wordlist to locate directories.

        How It Works:
        - Enter a valid domain name (e.g., example.com).
        - The tool validates the domain and starts performing the above tasks sequentially.
        - Results are logged to a JSON file (web_enumeration_results.json) for further analysis.

        Requirements:
        - Ensure an active internet connection.
        - Python libraries: requests, threading, json, and BeautifulSoup.

        Usage:
        - Run the script and provide the target domain.
        - Choose an option from the menu to start enumeration or view the manual.
        - Monitor the results saved in the JSON file and log file.
        """)

if __name__ == "__main__":
    target = input("Enter the target domain (e.g., example.com): ")
    tool = WebEnumerationTool(target)

    while True:
        print("\nOptions:")
        print("1. Run Enumeration")
        print("2. Show Manual")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            tool.run()
        elif choice == "2":
            tool.show_manual()
        elif choice == "3":
            print("Exiting the tool.")
            break
        else:
            print("Invalid choice. Please try again.")

