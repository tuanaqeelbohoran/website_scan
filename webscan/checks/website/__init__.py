"""checks/website/__init__.py — Registers all website checks."""
from checks.website.tls_cert        import TLSCertCheck
from checks.website.http_headers    import HTTPHeadersCheck
from checks.website.cookie_flags    import CookieFlagsCheck
from checks.website.redirect_chain  import RedirectChainCheck
from checks.website.cors_posture    import CORSPostureCheck
from checks.website.banner_leakage  import BannerLeakageCheck
from checks.website.robots_sitemap  import RobotsSitemapCheck
from checks.website.misconfig_hints import MisconfigHintsCheck
from checks.website.tech_fingerprint import TechFingerprintCheck
from checks.website.sensitive_paths  import SensitivePathsCheck

WEBSITE_CHECKS = [
    TLSCertCheck(),
    HTTPHeadersCheck(),
    CookieFlagsCheck(),
    RedirectChainCheck(),
    CORSPostureCheck(),
    BannerLeakageCheck(),
    RobotsSitemapCheck(),
    MisconfigHintsCheck(),
    TechFingerprintCheck(),
    SensitivePathsCheck(),
]
