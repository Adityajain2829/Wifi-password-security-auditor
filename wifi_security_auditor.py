"""
========================================================
    CODTECH IT SOLUTIONS - INTERNSHIP PROJECT
========================================================
Name      : Aditya Jain
Intern ID : CITS2742
Company   : CodTech IT Solutions
Domain    : Cyber Security & Ethical Hacking
Task      : Task 3 - WiFi Password Security Auditor
========================================================

DISCLAIMER:
    This tool only reads WiFi passwords already SAVED on
    YOUR OWN Windows device (via the built-in 'netsh wlan'
    command). It does not hack, crack, or intercept any
    external network. For EDUCATIONAL purposes only, as
    part of a cyber security internship task.
========================================================
"""

import subprocess
import re
import math
import datetime
import sys
import platform
from dataclasses import dataclass, field
from typing import Optional, List


# ============================================================
#  DATA MODEL
# ============================================================
@dataclass
class WifiProfile:
    ssid: str
    password: Optional[str]
    auth: str = "Unknown"
    cipher: str = "Unknown"


@dataclass
class PasswordVerdict:
    score: int
    rating: str
    entropy_bits: float
    strengths: list = field(default_factory=list)
    weaknesses: list = field(default_factory=list)


# ============================================================
#  PASSWORD STRENGTH ENGINE
# ============================================================
class PasswordAuditor:
    COMMON_PASSWORDS = {
        "password", "12345678", "qwerty123", "admin123", "welcome1",
        "password1", "iloveyou", "sunshine", "princess", "football",
        "letmein1", "monkey123", "dragon123"
    }
    SEQUENTIAL_PATTERN = re.compile(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|xyz)")
    REPEATED_CHAR_PATTERN = re.compile(r"(.)\1{2,}")

    def score(self, password: str) -> PasswordVerdict:
        strengths, weaknesses = [], []
        points = 0

        length = len(password)
        if length < 8:
            weaknesses.append(f"Too short ({length} chars, minimum 8 recommended)")
        elif length < 12:
            points += 1
            strengths.append(f"Acceptable length ({length} chars)")
        else:
            points += 2
            strengths.append(f"Strong length ({length} chars)")

        checks = [
            (r"[A-Z]", "uppercase letters", 1),
            (r"[a-z]", "lowercase letters", 1),
            (r"[0-9]", "digits", 1),
            (r"[^A-Za-z0-9]", "special characters", 2),
        ]
        for pattern, label, weight in checks:
            if re.search(pattern, password):
                points += weight
                strengths.append(f"Contains {label}")
            else:
                weaknesses.append(f"Missing {label}")

        if password.lower() in self.COMMON_PASSWORDS:
            points = 0
            weaknesses.append("Matches a widely-known common password")

        if self.SEQUENTIAL_PATTERN.search(password.lower()):
            points -= 1
            weaknesses.append("Contains a sequential pattern (e.g. 123, abc)")

        if self.REPEATED_CHAR_PATTERN.search(password):
            points -= 1
            weaknesses.append("Contains 3+ repeated characters in a row")

        points = max(0, min(points, 7))
        entropy = self._entropy(password)
        rating = self._rating(points)

        return PasswordVerdict(
            score=points, rating=rating, entropy_bits=entropy,
            strengths=strengths, weaknesses=weaknesses
        )

    @staticmethod
    def _entropy(password: str) -> float:
        pool = 0
        if re.search(r"[a-z]", password):
            pool += 26
        if re.search(r"[A-Z]", password):
            pool += 26
        if re.search(r"[0-9]", password):
            pool += 10
        if re.search(r"[^A-Za-z0-9]", password):
            pool += 32
        if pool == 0 or not password:
            return 0.0
        return round(len(password) * math.log2(pool), 2)

    @staticmethod
    def _rating(points: int) -> str:
        if points <= 2:
            return "WEAK"
        if points <= 4:
            return "MODERATE"
        if points <= 6:
            return "STRONG"
        return "VERY STRONG"


# ============================================================
#  WINDOWS WIFI PROFILE READER
# ============================================================
class WindowsWifiReader:
    """Reads saved WiFi profiles + passwords using netsh (Windows only)."""

    def list_profiles(self) -> List[WifiProfile]:
        if platform.system() != "Windows":
            raise RuntimeError("WindowsWifiReader can only run on Windows.")

        names = self._profile_names()
        profiles = []
        for name in names:
            profiles.append(self._profile_detail(name))
        return profiles

    def _profile_names(self) -> List[str]:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True
        )
        return [m.strip() for m in re.findall(r"All User Profile\s*:\s*(.+)", result.stdout)]

    def _profile_detail(self, name: str) -> WifiProfile:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "profile", f"name={name}", "key=clear"],
                capture_output=True, text=True
            )
            pwd_match = re.search(r"Key Content\s*:\s*(.+)", result.stdout)
            auth_match = re.search(r"Authentication\s*:\s*(.+)", result.stdout)
            cipher_match = re.search(r"Cipher\s*:\s*(.+)", result.stdout)

            return WifiProfile(
                ssid=name,
                password=pwd_match.group(1).strip() if pwd_match else None,
                auth=auth_match.group(1).strip() if auth_match else "Unknown",
                cipher=cipher_match.group(1).strip() if cipher_match else "Unknown",
            )
        except Exception:
            return WifiProfile(ssid=name, password=None)


# ============================================================
#  REPORT BUILDER
# ============================================================
class AuditReport:
    def __init__(self, auditor: PasswordAuditor):
        self.auditor = auditor
        self.entries = []   # list of (WifiProfile, PasswordVerdict | None)

    def build(self, profiles: List[WifiProfile]):
        self.entries = []
        for profile in profiles:
            verdict = self.auditor.score(profile.password) if profile.password else None
            self.entries.append((profile, verdict))

    @staticmethod
    def _mask(password: str) -> str:
        if len(password) <= 2:
            return "**"
        return password[0] + "*" * (len(password) - 2) + password[-1]

    def print_console(self):
        print("\n" + "=" * 60)
        print("        WiFi PASSWORD SECURITY AUDIT REPORT")
        print("=" * 60)
        print(f"Date     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Networks : {len(self.entries)} saved profile(s) found")
        print("=" * 60)

        for i, (profile, verdict) in enumerate(self.entries, 1):
            print(f"\n[{i}] SSID: {profile.ssid}")
            print(f"     Security : {profile.auth} / {profile.cipher}")
            if verdict is None:
                print("     Password : [not saved / hidden]")
                continue
            masked = self._mask(profile.password)
            print(f"     Password : {masked}")
            print(f"     Rating   : {verdict.rating}  (score {verdict.score}/7)")
            print(f"     Entropy  : {verdict.entropy_bits} bits")
            if verdict.weaknesses:
                print("     Weaknesses:")
                for w in verdict.weaknesses:
                    print(f"       - {w}")

        self._print_summary()

    def _print_summary(self):
        counts = {"WEAK": 0, "MODERATE": 0, "STRONG": 0, "VERY STRONG": 0, "NONE": 0}
        for _, verdict in self.entries:
            if verdict is None:
                counts["NONE"] += 1
            else:
                counts[verdict.rating] += 1

        print("\n" + "=" * 60)
        print("        AUDIT SUMMARY")
        print("=" * 60)
        print(f"Total networks   : {len(self.entries)}")
        print(f"  Weak           : {counts['WEAK']}")
        print(f"  Moderate       : {counts['MODERATE']}")
        print(f"  Strong         : {counts['STRONG']}")
        print(f"  Very strong    : {counts['VERY STRONG']}")
        print(f"  No password    : {counts['NONE']}")

        if counts["WEAK"] > 0:
            print(f"\n!! {counts['WEAK']} weak WiFi password(s) found.")
            print("   Consider changing them to something stronger.")
        else:
            print("\nNo weak passwords found among saved networks.")
        print("=" * 60)

    def render_text(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("  CODTECH IT SOLUTIONS - WiFi SECURITY AUDIT REPORT")
        lines.append("  Intern: Aditya Jain | ID: CITS2742")
        lines.append(f"  Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)

        for i, (profile, verdict) in enumerate(self.entries, 1):
            lines.append(f"\n[{i}] SSID: {profile.ssid}")
            lines.append(f"     Security : {profile.auth} / {profile.cipher}")
            if verdict is None:
                lines.append("     Password : [not saved / hidden]")
                continue
            lines.append(f"     Password : {self._mask(profile.password)}")
            lines.append(f"     Rating   : {verdict.rating}  (score {verdict.score}/7)")
            lines.append(f"     Entropy  : {verdict.entropy_bits} bits")
            for w in verdict.weaknesses:
                lines.append(f"       - {w}")
        return "\n".join(lines)

    def save(self, path: str = None) -> str:
        if path is None:
            path = f"wifi_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.render_text() + "\n")
        return path


# ============================================================
#  SECURITY TIPS (reference content)
# ============================================================
SECURITY_TIPS = """
  WiFi SECURITY BEST PRACTICES
  -----------------------------
  1. Use WPA2 or WPA3 encryption - never WEP (trivially broken)
  2. Use a password with 12+ characters mixing case, digits, symbols
  3. Avoid dictionary words, names, or birthdays in your password
  4. Change the router's default admin password
  5. Disable WPS if you don't actively use it
  6. Keep router firmware up to date
  7. Consider a guest network for visitors/IoT devices
"""


# ============================================================
#  CLI ENTRY POINT
# ============================================================
BANNER = """
============================================================
   WiFi PASSWORD SECURITY AUDITOR
   CodTech IT Solutions - Cyber Security Internship
   Intern: Aditya Jain | ID: CITS2742
============================================================

DISCLAIMER: Reads WiFi passwords already saved on THIS
device only. Does not access or attack any other network.
"""


def run_audit():
    reader = WindowsWifiReader()
    print("\nScanning saved WiFi profiles...")
    try:
        profiles = reader.list_profiles()
    except RuntimeError as e:
        print(f"Error: {e}")
        return

    if not profiles:
        print("No saved WiFi profiles found on this device.")
        return

    auditor = PasswordAuditor()
    report = AuditReport(auditor)
    report.build(profiles)
    report.print_console()

    choice = input("\nSave this audit report to a file? (y/n): ").strip().lower()
    if choice == "y":
        path = report.save()
        print(f"Saved -> {path}")


def main():
    print(BANNER)

    if platform.system() != "Windows":
        print("This tool relies on Windows' 'netsh wlan' command and only")
        print("runs on Windows. Please run it on your Windows machine.")
        sys.exit(1)

    while True:
        print("\nOptions:")
        print("  [1] Scan & audit saved WiFi passwords")
        print("  [2] Show WiFi security best practices")
        print("  [3] Exit")

        choice = input("\nEnter choice (1-3): ").strip()
        if choice == "1":
            run_audit()
        elif choice == "2":
            print(SECURITY_TIPS)
        elif choice == "3":
            print("\nExiting. Stay secure!\n")
            break
        else:
            print("Invalid choice, try again.")


if __name__ == "__main__":
    main()
