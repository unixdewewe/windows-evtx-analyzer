"""Dynamic channel-to-normalizer router."""

from src.normalizers.base import BaseNormalizer
from src.normalizers.security import SecurityNormalizer
from src.normalizers.sysmon import SysmonNormalizer
from src.normalizers.powershell import PowerShellNormalizer
from src.normalizers.domain import DomainNormalizer
from src.normalizers.persistence import PersistenceNormalizer
from src.normalizers.defense_network import DefenseNetworkNormalizer
from src.normalizers.session_wmi import SessionWmiNormalizer
from src.normalizers.generic import GenericNormalizer


class NormalizerRegistry:
    """Routes .evtx files or channels to specialized or fallback normalizers."""

    def __init__(self):
        self._domain_normalizer = DomainNormalizer()
        self._security_normalizer = SecurityNormalizer()
        self.normalizers = {
            "security.evtx": self._security_normalizer,
            "sysmon": SysmonNormalizer(),
            "powershell": PowerShellNormalizer(),
            "directory service": self._domain_normalizer,
            "dns": DefenseNetworkNormalizer(),
            "taskscheduler": PersistenceNormalizer(),
            "grouppolicy": PersistenceNormalizer(),
            "applocker": PersistenceNormalizer(),
            "windows defender": DefenseNetworkNormalizer(),
            "firewall": DefenseNetworkNormalizer(),
            "bits-client": DefenseNetworkNormalizer(),
            "terminalservices": SessionWmiNormalizer(),
            "winlogon": SessionWmiNormalizer(),
            "wmi-activity": SessionWmiNormalizer(),
        }
        self.fallback = GenericNormalizer()

    def get_normalizer(self, filename: str, raw_event: dict = None) -> BaseNormalizer:
        """Selects the appropriate normalizer based on filename and EventID."""
        clean_name = filename.lower()

        if raw_event and raw_event.get("EventID") in {4662, 4768, 4769, 4771, 5136, 5137, 5139}:
            return self._domain_normalizer

        for key, normalizer in self.normalizers.items():
            if key in clean_name:
                return normalizer

        return self.fallback
