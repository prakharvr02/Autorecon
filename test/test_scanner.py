import unittest
from src.core.scanner import AutoRecon

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.config = {...}
        self.scanner = AutoRecon("test.com", self.config)

    def test_subdomain_enumeration(self):
        self.scanner.enumerate_subdomains()
        self.assertGreater(len(self.scanner.results['subdomains']), 0)
