class AutoRecon:
    def __init__(self, domain, config):
        self.domain = domain
        self.config = config
        self.results = {
            "metadata": {
                "version": "1.0",
                "date": datetime.now().isoformat()
            },
            "findings": []
        }
        
    def run(self):
        """Execute complete scan workflow"""
        self.enumerate_subdomains()
        self.scan_ports()
        self.check_vulnerabilities()
        self.generate_reports()
