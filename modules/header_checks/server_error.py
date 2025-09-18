#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced server error analysis focused on server-side errors
"""
import re
import time
from typing import List, Optional, Tuple, Dict, Any, Set
from utils.utils import requests, configure_logger

logger = configure_logger(__name__)


class ServerErrorAnalyzer:
    """Analyseur d'erreurs serveur avec détection de comportements intéressants."""

    def __init__(self):
        # Payloads pour provoquer des erreurs serveur
        self.payloads_error = [
            "%2a",
            "%EXT%",
            "%ff",
            "%0A",
            "..%3B/",
            "..%3B",
            "%2e",
            "~",
            ".bak",
            ".old",
            ".tmp",
            "%00",
            "%0D",
            "A" * 100,
        ]

        # Technologies détectables dans les erreurs
        self.tech_signatures = {
            "apache": ["apache", "httpd"],
            "nginx": ["nginx"],
            "iis": ["microsoft-iis", "aspnet"],
            "php": ["x-powered-by: php", "php"],
            "java": ["jsessionid", "tomcat", "jetty"],
            "python": ["django", "flask", "wsgi"],
            ".net": ["aspnet", "asp.net"],
            "nodejs": ["express", "node.js"],
        }

        # Patterns révélateurs dans les erreurs serveur
        self.error_patterns = {
            "path_disclosure": r"([A-Za-z]:\\[^<>\s]*|/[a-zA-Z0-9_\-/]*\.(php|asp|jsp|py))",
            "version_info": r"(version\s+[\d\.]+|v[\d\.]+|\d+\.\d+\.\d+)",
            "database_error": r"(mysql|postgresql|oracle|mssql|sqlite)",
            "stack_trace": r"(traceback|stack trace|exception.*line\s+\d+)",
            "debug_mode": r"(debug|development|traceback|call stack)",
            "internal_ip": r"(\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b)",
        }

        self.user_agent = (
            "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
        )
        self.timeout = 10

    def _make_request(
        self, url: str, authent: Optional[Any] = None
    ) -> Optional[Tuple[requests.Response, float]]:
        """Effectue une requête avec mesure du temps."""
        try:
            start_time = time.time()
            response = requests.get(
                url,
                verify=False,
                headers={"User-agent": self.user_agent},
                timeout=self.timeout,
                auth=authent,
            )
            response_time = time.time() - start_time
            return response, response_time
        except requests.RequestException as e:
            logger.exception(f"Erreur requête {url}: {e}")
            return None

    def _detect_tech_from_error(
        self, headers: Dict[str, str], content: str
    ) -> Set[str]:
        """Détecte les technologies à partir des erreurs."""
        detected = set()
        all_text = (str(headers) + content).lower()

        for tech, signatures in self.tech_signatures.items():
            if any(sig in all_text for sig in signatures):
                detected.add(tech)
        return detected

    def _find_error_patterns(self, content: str) -> Dict[str, List[str]]:
        """Trouve des patterns intéressants dans les erreurs."""
        findings = {}
        for pattern_name, regex in self.error_patterns.items():
            matches = re.findall(regex, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings[pattern_name] = matches[:2]  # Max 2 exemples
        return findings

    def _analyze_error_response(
        self, payload: str, response: requests.Response, response_time: float
    ) -> None:
        """Analyse une réponse d'erreur et affiche les infos intéressantes."""
        content = response.text[:1000] if hasattr(response, "text") else ""

        # Info de base
        print(
            f" ├─ {response.status_code} error with {payload} [{len(response.content)} bytes, {response_time:.2f}s]"
        )

        # Détection de technologies
        tech_detected = self._detect_tech_from_error(dict(response.headers), content)
        if tech_detected:
            print(f"   🔍 Technologies: {', '.join(tech_detected)}")

        # Analyse des patterns d'erreur
        error_findings = self._find_error_patterns(content)
        if error_findings:
            for pattern_type, matches in error_findings.items():
                if pattern_type == "path_disclosure":
                    print(f"   📁 Path disclosure: {matches[0]}")
                elif pattern_type == "version_info":
                    print(f"   📋 Version info: {matches[0]}")
                elif pattern_type == "database_error":
                    print(f"   🗄️  Database error: {matches[0]}")
                elif pattern_type == "stack_trace":
                    print(f"   📊 Stack trace detected")
                elif pattern_type == "debug_mode":
                    print(f"   🐛 Debug mode detected")
                elif pattern_type == "internal_ip":
                    print(f"   🌐 Internal IP: {matches[0]}")

        # Headers intéressants spécifiques aux erreurs
        interesting_headers = [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-generator",
        ]
        for header in interesting_headers:
            if header in response.headers:
                print(f"   🏷️  {header}: {response.headers[header]}")

        # Contenu d'erreur verbose
        if response.status_code == 500 and len(content) > 500:
            print(f"   ⚠️  Verbose error message ({len(content)} chars)")
            # Échantillon nettoyé
            sample = re.sub(r"<[^>]+>", "", content[:200]).strip()
            if sample:
                print(f"   📄 Sample: {sample[:100]}...")

        # Réponse lente (potentiel DoS)
        if response_time > 3.0:
            print(f"   🐌 Slow response ({response_time:.2f}s) - potential DoS vector")

    def analyze_server_errors(
        self,
        url: str,
        base_headers: List[str],
        authent: Optional[Any] = None,
        url_file: bool = False,
    ) -> bool:
        """Analyse les erreurs serveur avec détection comportementale."""
        print("\033[36m ├ Server error analysis\033[0m")

        found_errors = False

        for payload in self.payloads_error:
            # Construction URL d'erreur
            if url.endswith("/"):
                error_url = f"{url}{payload}"
            else:
                error_url = f"{url}/{payload}"

            # Requête
            result = self._make_request(error_url, authent)
            if not result:
                print(f" ! Request failed for {payload}")
                continue

            response, response_time = result

            # Analyse seulement les codes d'erreur serveur
            if response.status_code in [400, 401, 403, 404, 500, 501, 502, 503]:
                found_errors = True
                self._analyze_error_response(payload, response, response_time)

        if not found_errors:
            print(" ├─ No interesting server errors found")

        return found_errors


def get_server_error(
    url: str,
    base_header: List[str],
    authent: Optional[Any] = None,
    url_file: bool = False,
) -> bool:
    """Fonction wrapper pour maintenir la compatibilité."""
    analyzer = ServerErrorAnalyzer()
    return analyzer.analyze_server_errors(url, base_header, authent, url_file)
