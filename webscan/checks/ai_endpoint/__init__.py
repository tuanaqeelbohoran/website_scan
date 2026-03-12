"""checks/ai_endpoint/__init__.py — Registers all AI endpoint checks."""
from checks.ai_endpoint.tls_auth              import TLSAuthCheck
from checks.ai_endpoint.rate_limit_headers    import RateLimitHeadersCheck
from checks.ai_endpoint.cors_check            import AICORSCheck
from checks.ai_endpoint.content_type          import ContentTypeCheck
from checks.ai_endpoint.openapi_discovery     import OpenAPIDiscoveryCheck
from checks.ai_endpoint.error_leakage         import ErrorLeakageCheck
from checks.ai_endpoint.pii_signal            import PIISignalCheck
from checks.ai_endpoint.prompt_injection_rubric import PromptInjectionRubricCheck
from checks.ai_endpoint.data_retention_policy import DataRetentionPolicyCheck
from checks.ai_endpoint.jailbreak_posture     import JailbreakPostureCheck

AI_CHECKS = [
    TLSAuthCheck(),
    RateLimitHeadersCheck(),
    AICORSCheck(),
    ContentTypeCheck(),
    OpenAPIDiscoveryCheck(),
    ErrorLeakageCheck(),
    PIISignalCheck(),
    PromptInjectionRubricCheck(),
    DataRetentionPolicyCheck(),
    JailbreakPostureCheck(),
]
