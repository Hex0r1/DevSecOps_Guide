**Some Basics:****

for Python web apps, popular python backend technologies are: (Django, Flask, or FastAPI)
https://blog.appsignal.com/2025/06/25/flask-or-django-which-best-fits-your-python-project.html
https://blog.appsignal.com/2025/02/26/an-introduction-to-flask-sqlalchemy-in-python.html

# Secure Python Programming (Django/REST API): Resources, Standards, Frameworks, and Coding Examples

As a seasoned software development mentor, this guide provides a comprehensive overview of secure Python programming with a focus on backend technologies like Django and Django REST Framework (DRF). It draws from established best practices to help developers at all levels build resilient applications. The focus is on current standards as of October 2025, emphasizing Django 5.2 and DRF 3.15+ features where applicable, such as enhanced ORM security and API throttling, while avoiding outdated practices like raw SQL queries without parameterization or weak password hashing.

## Resources

This section lists well-regarded resources for learning secure Python/Django/REST API programming, including official documentation, books, online courses, and community forums. These are selected for their relevance, practicality, and alignment with modern security standards.

### Official Documentation
- **Django Security Documentation** - Overview of Django's built-in security features, including CSRF protection, SQL injection prevention via ORM, and HTTPS enforcement. Updated for Django 5.2 with guidance on API-specific threats.
- **OWASP Django Security Cheat Sheet** - Practical tips for securing Django apps, covering common vulnerabilities like injection and XSS, with Django-specific mitigations.
- **Django REST Framework Documentation** - Covers authentication, permissions, and throttling for secure APIs, including best practices for JWT and OAuth integration.

### Books
- **Full Stack Python Security by Dennis Byrne (Manning Publications)** - Teaches cryptography, TLS, and attack resistance for Python and Django web apps, with hands-on examples for securing backends.
- **Django for APIs by William Vincent** - Focuses on building secure REST APIs with DRF, including authentication, permissions, and testing for vulnerabilities like broken access control.
- **Two Scoops of Django 3.x** - Best practices for Django development, with chapters on security patterns like secure configuration and dependency management (concepts remain relevant for Django 5).

### Online Courses
- **Python & Django REST API Bootcamp on Udemy** - Comprehensive course on building secure web APIs, covering OWASP risks, authentication, and rate limiting with DRF.
- **Django for Everybody Specialization on Coursera** - Covers Django backend development with modules on security best practices, including secure API design and data validation.
- **Django Online Training with REST API by NareshIT** - Hands-on training emphasizing secure coding, API security, and integration with tools like Celery for task security.

### Community Forums
- **Reddit: r/django** - Active discussions on Django security, including API best practices, vulnerability scans, and resource recommendations.
- **Stack Overflow** - Q&A for troubleshooting Django/DRF security issues, with tags for OWASP and secure coding.
- **Django Forum** - Official community for in-depth advice on securing Django applications and REST APIs.

## Standards

Standards provide formalized rules to defend against common threats. These are essential for aligning Python/Django development with industry best practices.

- **OWASP Top 10 (2021 Edition, with 2025 Updates)** - Critical web risks like Injection and Broken Access Control; apply to Django via ORM for injection prevention and DRF permissions for access control. The API-specific variant addresses REST endpoints.
- **OWASP API Security Top 10 (2023 Edition)** - Tailored for APIs, covering risks like Broken Object Level Authorization; mitigate in DRF with custom permissions and inventory management.
- **Django Security Guidelines** - Official advice on preventing XSS, CSRF, and clickjacking, integrated into Django's core features.
- **CERT Secure Coding Standards for Python** - Focuses on secure Python practices, including exception handling and resource management to avoid breaches.

## Frameworks

Frameworks and tools offer structured approaches for integrating security into Python/Django/REST API development.

- **Microsoft Security Development Lifecycle (SDL)** - DevSecOps process with threat modeling and scans; apply to Django projects via CI/CD tools like GitHub Actions for vulnerability checks.
- **Django Built-in Security Features** - Includes CSRF middleware, auto-escaping in templates, and ORM parameterization. In Django 5.2, enhancements support better API rate limiting.
- **Django REST Framework Security Tools** - Permissions classes, authentication backends (e.g., TokenAuthentication), and throttling for API protection.
- **Supporting Libraries** - django-cors-headers for secure cross-origin requests, django-guardian for object-level permissions, and safety for dependency scanning.

## Coding Examples: Secure Python/Django Cheat Sheet

This cheat sheet-style guide highlights common vulnerabilities from OWASP Top 10, with brief descriptions, vulnerable code examples, and secure mitigations using Django/DRF best practices. Examples are in Python for Django 5.2/DRF, focusing on practical API scenarios.

| Vulnerability | Description | Vulnerable Code Example | Secure Code Example & Mitigation |
|---------------|-------------|-------------------------|---------------------------|
| **A01: Broken Access Control** | Unauthorized API access, e.g., via missing permission checks in views. | ```python
| **A02: Cryptographic Failures** | Weak hashing exposes passwords; avoid plain text or MD5 in Django. | ```python<br>user.password = plain_password  # No hashing<br>user.save()<br>``` | Use secure hashing: ```python<br>from django.contrib.auth.hashers import make_password<br>user.password = make_password(plain_password)<br>user.save()<br>``` Mitigation: Rely on Django's PBKDF2 default; use Argon2 for high-security needs. |
| **A03: Injection** | Unsanitized input causes SQL injection in queries. | ```python<br>from django.db import connection<br>cursor = connection.cursor()<br>cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")<br>``` | Use ORM parameterization: ```python<br>users = User.objects.filter(name=user_input)<br>``` Mitigation: Always use Django ORM or cursor executemany() to bind parameters safely. |
| **A04: Insecure Design** | Flaws like missing threat modeling in API design. | N/A (design-level) | Incorporate SDL: Use STRIDE modeling during design; validate inputs with DRF serializers. Mitigation: Apply least privilege in viewsets. |
| **A05: Security Misconfiguration** | Exposed debug mode or weak settings in production. | ```python<br># settings.py<br>DEBUG = True  # In production<br>``` | Secure settings: ```python<br># settings.py<br>DEBUG = False<br>ALLOWED_HOSTS = ['yourdomain.com']<br>SECURE_SSL_REDIRECT = True<br>``` Mitigation: Use environment variables and django-environ for config; enable HSTS. |
| **A06: Vulnerable Components** | Outdated packages like old DRF versions. | N/A (dependency-level) | Scan dependencies: Use `pip-audit` or safety CLI. Mitigation: Pin versions in requirements.txt and integrate into CI/CD. |
| **A07: Identification and Authentication Failures** | Weak API auth, e.g., no token validation. | ```python<br>from rest_framework.decorators import api_view<br>@api_view(['POST'])<br>def login(request):<br>    # No validation<br>    return Response({'token': 'fake_token'})<br>``` | Secure auth: ```python<br>from rest_framework.authtoken.views import ObtainAuthToken<br>class CustomAuthToken(ObtainAuthToken):<br>    throttle_classes = [AnonRateThrottle]<br>    # Custom throttling<br>``` Mitigation: Use DRF's TokenAuthentication with expiration and rate limiting. |
| **A08: Software and Data Integrity Failures** | Insecure deserialization or unverified updates. | ```python<br>import pickle<br>data = pickle.loads(serialized_data)<br>``` | Safe alternative: ```python<br>from django.core import serializers<br>data = serializers.deserialize('json', json_data)<br>``` Mitigation: Use JSON/XML serializers; avoid pickle for untrusted input. |
| **A09: Security Logging and Monitoring Failures** | Inadequate logs miss attacks. | ```python<br>print(f"Error: {error}")<br>``` | Structured logging: ```python<br>import logging<br>logger = logging.getLogger(__name__)<br>logger.error("API error", extra={'user': request.user.id, 'error': str(error)})<br>``` Mitigation: Use Django's logging with Sentry integration for alerts. |
| **A10: Server-Side Request Forgery (SSRF)** | Unvalidated URLs in API requests. | ```python<br>import requests<br>response = requests.get(user_url)<br>``` | Validate URLs: ```python<br>from urllib.parse import urlparse<br>def is_safe_url(url):<br>    parsed = urlparse(url)<br>    return parsed.netloc in ALLOWED_DOMAINS<br>if is_safe_url(user_url):<br>    response = requests.get(user_url)<br>``` Mitigation: Whitelist domains and use libraries like furl for parsing. |

This cheat sheet is not exhaustive; refer to the OWASP Django REST Framework Cheat Sheet for more details. Always test with tools like Bandit for static analysis or OWASP ZAP for dynamic scanning.

# Secure FastAPI Development: Resources, Standards, Frameworks, and Coding Examples

As a seasoned software development mentor, this guide provides a comprehensive overview of secure FastAPI development. It draws from established best practices to help developers at all levels build resilient APIs. The focus is on current standards as of October 2025, emphasizing FastAPI 0.115+ features where applicable, such as enhanced Pydantic validation and async security dependencies, while avoiding outdated practices like manual SQL queries without parameterization or weak JWT handling.

## Resources

This section lists well-regarded resources for learning secure FastAPI programming, including official documentation, books, online courses, and community forums. These are selected for their relevance, practicality, and alignment with modern security standards.

### Official Documentation
- **FastAPI Security Tutorial** - Covers OAuth2, OpenID Connect, and security schemes like API keys and HTTP Basic, with utilities in `fastapi.security` for easy integration and automatic OpenAPI documentation.
- **FastAPI Best Practices Repository** - Opinionated conventions for production FastAPI apps, including security patterns like dependency injection for auth and input validation.
- **OWASP API Security Project** - Tailored guidance for API risks, with FastAPI-specific examples for mitigating vulnerabilities like broken authentication.

### Books
- **The Ultimate FastAPI Handbook: Build Scalable, Secure, and Production-Ready APIs** - Hands-on guide to FastAPI for microservices and REST APIs, emphasizing security with JWT, rate limiting, and OWASP compliance.
- **FastAPI (O'Reilly Media)** - Comprehensive coverage of FastAPI development, including RESTful APIs and security best practices for web applications.
- **New FastAPI Books for 2025 (BookAuthority Recommendations)** - Curated list of recent titles focusing on advanced security, async patterns, and deployment.

### Online Courses
- **FastAPI - The Complete Course 2025 (Beginner + Advanced) on Udemy** - Builds and deploys secure FastAPI apps, covering RESTful APIs, authentication, and full-stack integration.
- **7 Best Udemy Courses to Learn FastAPI in 2025** - Top-rated courses with modules on secure API design, vulnerability testing, and best practices.
- **Modern APIs with FastAPI, Pydantic, and Python (TalkPython Training)** - Teaches secure API building with async/await, data validation, and cloud deployment.

### Community Forums
- **Reddit: r/FastAPI** - Discussions on security extensions, vulnerability recreations, and best practices for FastAPI apps.
- **GitHub Awesome FastAPI** - Curated list of resources, including security-focused tutorials and full web app courses.
- **Stack Overflow** - Q&A for FastAPI security issues, with tags for OWASP and authentication.

## Standards

Standards provide formalized rules to defend against common threats. These are essential for aligning FastAPI development with industry best practices.

- **OWASP API Security Top 10 (2023 Edition)** - Focuses on API-specific risks like Broken Object Level Authorization and Broken Authentication; apply to FastAPI via dependency-based permissions and Pydantic for validation.
- **OWASP Top 10 for Web Applications (2021, with API Extensions)** - Covers general risks adaptable to FastAPI, such as Injection and Security Misconfiguration, with tools for testing endpoints.
- **FastAPI Security Best Practices** - Guidelines for HTTPS enforcement, input sanitization, and automated testing aligned with OWASP.

## Frameworks

Frameworks and tools offer structured approaches for integrating security into FastAPI development.

- **Microsoft Security Development Lifecycle (SDL)** - DevSecOps process with threat modeling; integrate into FastAPI via CI/CD for scans and static analysis.
- **FastAPI Built-in Security Features** - Supports OAuth2 flows, OpenID Connect, and security schemes (e.g., Bearer tokens, API keys) via `fastapi.security`; uses dependencies for reusable auth logic. In 0.115+, improved async support enhances secure data handling.
- **FastAPI Guard** - Extension for middleware-based security, including rate limiting and CORS protection.
- **Supporting Libraries** - SecurePy for HTTP security headers, Pydantic for validation, and libraries like python-jose for JWT; use OWASP ZAP for testing.

## Coding Examples: Secure FastAPI Cheat Sheet

This cheat sheet-style guide highlights common vulnerabilities from OWASP API Security Top 10, with brief descriptions, vulnerable code examples, and secure mitigations using FastAPI best practices. Examples are in Python for FastAPI 0.115+, focusing on practical API scenarios.

| Vulnerability | Description | Vulnerable Code Example | Secure Code Example & Mitigation |
|---------------|-------------|-------------------------|---------------------------|
| **API1: Broken Object Level Authorization** | Unauthorized access to objects, e.g., via ID manipulation in endpoints. | ```python
| **API2: Broken Authentication** | Weak auth mechanisms, e.g., no token expiration. | ```python<br>@app.post("/login")<br>def login(username: str, password: str):<br>    if username == "admin" and password == "pass":  # Plain text<br>        return {"token": "static_token"}<br>``` | Secure JWT: ```python<br>from jose import jwt<br>from passlib.context import CryptContext<br>pwd_context = CryptContext(schemes=["bcrypt"])<br>@app.post("/login")<br>def login(form_data: OAuth2PasswordRequestForm = Depends()):<br>    user = verify_user(form_data.username, form_data.password)<br>    if not user: raise HTTPException(401)<br>    token = jwt.encode({"sub": user.username, "exp": time.time() + 3600}, SECRET_KEY)<br>    return {"access_token": token, "token_type": "bearer"}<br>``` Mitigation: Use OAuth2PasswordBearer and hashed passwords with expiration. |
| **API3: Broken Object Property Level Authorization** | Exposure of sensitive properties without checks. | ```python<br>@app.get("/users/{user_id}/profile")<br>def get_profile(user_id: int):<br>    return user.profile  # Includes sensitive fields<br>``` | Filter with Pydantic: ```python<br>from pydantic import BaseModel<br>class UserProfile(BaseModel):<br>    name: str<br>    # Exclude sensitive: email, etc.<br>class SecureProfile(UserProfile):<br>    model_config = {"from_attributes": True}<br>@app.get("/users/{user_id}/profile", response_model=SecureProfile)<br>def get_profile(user_id: int, current_user = Depends(get_current_user)):<br>    if user_id != current_user.id: raise HTTPException(403)<br>    return user_by_id(user_id)<br>``` Mitigation: Use response models to exclude properties and auth dependencies. |
| **API4: Unrestricted Resource Consumption** | No rate limiting leads to DoS. | ```python<br>@app.get("/data")<br>def get_data():<br>    time.sleep(10)  # No limit<br>    return {"data": "heavy"}<br>``` | Add throttling: ```python<br>from slowapi import Limiter, _rate_limit_exceeded_handler<br>from slowapi.util import get_remote_address<br>limiter = Limiter(key_func=get_remote_address)<br>app.state.limiter = limiter<br>app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)<br>@app.get("/data")<br>@limiter.limit("5/minute")<br>def get_data(request: Request):<br>    return {"data": "heavy"}<br>``` Mitigation: Integrate slowapi for rate limiting based on IP or user. |
| **API5: Broken Function Level Authorization** | Missing role checks for functions. | ```python<br>@app.post("/admin/users")<br>def create_user():<br>    # No role check<br>    return {"created": True}<br>``` | Role-based deps: ```python<br>def require_role(role: str):<br>    def dep(current_user = Depends(get_current_user)):<br>        if current_user.role != role: raise HTTPException(403)<br>        return current_user<br>    return dep<br>@app.post("/admin/users")<br>def create_user(admin = Depends(require_role("admin"))):<br>    return {"created": True}<br>``` Mitigation: Use dependency factories for role enforcement. |
| **API6: Unrestricted Access to Sensitive Business Flows** | Exposed sensitive endpoints without monitoring. | N/A (flow-level) | Log and monitor: ```python<br>import logging<br>logger = logging.getLogger(__name__)<br>@app.post("/payment")<br>def process_payment(data: dict, current_user = Depends(get_current_user)):<br>    logger.info(f"Payment attempt by {current_user.id}")<br>    # Process with validation<br>    return {"status": "processed"}<br>``` Mitigation: Integrate logging (e.g., structlog) and audit sensitive flows. |
| **API7: Server-Side Request Forgery** | Unvalidated external calls. | ```python<br>import requests<br>@app.get("/fetch")<br>def fetch(url: str):<br>    return requests.get(url).json()  # Unsafe<br>``` | Whitelist validation: ```python<br>ALLOWED_DOMAINS = ["api.example.com"]<br>from urllib.parse import urlparse<br>def safe_url(url: str):<br>    domain = urlparse(url).netloc<br>    if domain not in ALLOWED_DOMAINS: raise HTTPException(400)<br>    return url<br>@app.get("/fetch")<br>def fetch(url: str = Depends(safe_url)):<br>    return requests.get(url).json()<br>``` Mitigation: Validate and whitelist URLs in dependencies. |
| **API8: Security Misconfiguration** | Default or exposed configs. | ```python<br># main.py<br>app = FastAPI(debug=True)  # In prod<br>``` | Secure config: ```python<br>from environs import Env<br>env = Env()<br>env.read_env()<br>app = FastAPI(debug=env.bool("DEBUG", False))<br>if not app.debug:<br>    # Add security middleware<br>    from fastapi.middleware.cors import CORSMiddleware<br>    app.add_middleware(CORSMiddleware, allow_origins=[env.str("ALLOWED_ORIGINS")], allow_credentials=True)<br>``` Mitigation: Use environs for env vars and middleware for CORS/headers. |
| **API9: Improper Inventory Management** | Undocumented or shadow APIs. | N/A (management-level) | Document all: Use FastAPI's auto-docs; scan with tools like API inventory scripts. Mitigation: Maintain endpoint registry and use OpenAPI tags. |
| **API10: Unsafe Consumption of APIs** | Lack of input validation. | ```python<br>@app.post("/items")<br>def create_item(item: dict):  # No schema<br>    return item<br>``` | Pydantic validation: ```python<br>from pydantic import BaseModel<br>class Item(BaseModel):<br>    name: str<br>    price: float = Field(gt=0)<br>@app.post("/items")<br>def create_item(item: Item):<br>    # Auto-validated<br>    return item<br>``` Mitigation: Enforce schemas with Pydantic for type-safe inputs. |

This cheat sheet is not exhaustive; refer to OWASP API Security Top 10 for more details. Always test with tools like OWASP ZAP or Bandit for static analysis.

**General security**
https://medium.com/@hayley_5495/python-security-best-practices-cheat-sheet-snyk-ce463c8d4670
https://www.isecure-journal.com/article_150541_a9f0526e45cd43bc510cc2945ddfcf80.pdf
https://snyk.io/blog/python-security-best-practices-cheat-sheet/
https://go.snyk.io/rs/677-THP-415/images/Python_Cheatsheet_whitepaper.pdf
https://medium.com/@melihcolpan/python-web-applications-how-to-secure-against-common-vulnerabilities-65247d20acce


**Django**
https://cheatsheetseries.owasp.org/cheatsheets/Django_Security_Cheat_Sheet.html
https://cheatsheetseries.owasp.org/cheatsheets/Django_REST_Framework_Cheat_Sheet.html
https://docs.djangoproject.com/en/5.2/topics/security/
https://escape.tech/blog/best-django-security-practices/



**Flask**
https://app-generator.dev/docs/technologies/flask/index.html
https://snyk.io/blog/secure-python-flask-applications/
https://escape.tech/blog/best-practices-protect-flask-applications/







