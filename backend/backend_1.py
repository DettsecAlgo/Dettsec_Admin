# --- START OF FILE backend_merged.py ---

#!/usr/bin/env python3
import os
import sys
import json
import logging
import requests
import asyncio
import hashlib
import traceback
import threading
import time
import re # For robust URL parsing and log parsing
from contextlib import asynccontextmanager # For lifespan
from datetime import datetime, timedelta, timezone # Added timezone awareness
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs
from pathlib import Path # For log file path handling
from typing import List, Optional, Dict, Any # For type hinting

# Selenium imports grouped
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException, NoSuchElementException, WebDriverException
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

# FastAPI and related imports
from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Database imports
from sqlalchemy import create_engine, Column, Integer, String, DateTime, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# Security and Utilities imports
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import pyotp
from jose import JWTError, jwt # type: ignore
from pydantic import BaseModel, Field

load_dotenv()

# -------------------- Logging Setup --------------------
LOG_FILE_NAME = "flattrade_app.log" # Consistent log file name
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s:%(threadName)s: %(message)s", # Include threadName
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE_NAME),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("multi_tenant_flattrade_production") # Consistent logger name

# -------------------- Environment Variables & Config --------------------
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "user")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "pass123")
DB_PORT = os.environ.get("DB_PORT", "5432")

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
CHROMEDRIVER_PATH = os.environ.get("CHROMEDRIVER_PATH", r"C:\webdriver\chromedriver.exe")

# --- Admin Credentials & JWT Config (Imported from Script 1) ---
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "adminpassword") # Plain text as requested
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "a_very_secret_key_for_jwt_please_change") # CHANGE THIS IN PRODUCTION!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8 # 8 hours validity

# --- Validation Checks ---
if not DB_NAME or not DB_PASSWORD:
    logger.critical("DB_NAME and DB_PASSWORD environment variables must be set!")
    sys.exit(1)
if not ENCRYPTION_KEY:
    logger.critical("ENCRYPTION_KEY environment variable not set!")
    sys.exit(1)
if JWT_SECRET_KEY == "a_very_secret_key_for_jwt_please_change":
     logger.warning("Using default JWT_SECRET_KEY. Please set a strong secret in your .env file!")
if ADMIN_PASSWORD == "adminpassword":
     logger.warning("Using default ADMIN_PASSWORD. Please set a secure password in your .env file!")

# -------------------- Database Connection --------------------
CONNECTION_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
logger.info(f"Using PostgreSQL connection URL (password hidden)")
engine = create_engine(CONNECTION_URL, pool_pre_ping=True, pool_recycle=3600)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -------------------- Tenant Model (From Script 1 - timezone aware) --------------------
class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String, unique=True, nullable=False, index=True)
    uder_id = Column(String, nullable=False) # Original typo kept
    encrypted_password = Column(String, nullable=False)
    api_key = Column(String, nullable=False)
    api_secret = Column(String, nullable=False)
    totp_key = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    authtoken = Column(String, nullable=True)
    default_qty = Column(Integer, nullable=True)
    # Use timezone aware datetime from Script 1
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Tenant(tenant_id='{self.tenant_id}', uder_id='{self.uder_id}')>"

try:
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created or verified.")
except Exception as e:
    logger.critical(f"Database initialization failed: {str(e)}")
    sys.exit(1)

# Dependency to get DB session (From Script 1)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------- Encryption Utilities (Consistent across both) --------------------
try:
    fernet = Fernet(ENCRYPTION_KEY.encode() if not isinstance(ENCRYPTION_KEY, bytes) else ENCRYPTION_KEY)
except Exception as e:
    logger.critical(f"Failed to initialize encryption: {str(e)}")
    sys.exit(1)

def encrypt_password(plain_text: str) -> str:
    try:
        return fernet.encrypt(plain_text.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise
def decrypt_password(cipher_text: str) -> str:
    try:
        return fernet.decrypt(cipher_text.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise

# -------------------- Global Constants (Merged & Refined) --------------------
AUTH_URL = "https://auth.flattrade.in/?app_key="
DEFAULT_EXCHANGE = "MCX"
DEFAULT_RETENTION = "DAY"
DEFAULT_REMARKS = "Order placed via API"
BASE_FLATTRADE_URL = "https://piconnect.flattrade.in/PiConnectTP"
PLACE_ORDER_ENDPOINT = f"{BASE_FLATTRADE_URL}/PlaceOrder"
AUTH_RETRY_COUNT = 3
AUTH_RETRY_DELAY = 5  # seconds
SELENIUM_ELEMENT_TIMEOUT = 15
SELENIUM_INTERACTION_RETRIES = 3
SELENIUM_INTERACTION_RETRY_DELAY = 0.5
SELENIUM_REDIRECT_TIMEOUT = 90
INITIAL_AUTH_MAX_WORKERS = 5 # Max concurrent initial authentications (adjustable)
ORDER_EXEC_MAX_WORKERS = 10 # Max concurrent order placements (adjustable)

# -------------------- Authenticator Class (Refined version from both scripts) --------------------
class AuthenticationError(Exception):
    """Custom exception for authentication errors."""
    pass

class Authenticator:
    def __init__(self, chromedriver_path, auth_url, tenant_credentials,
                 element_timeout=SELENIUM_ELEMENT_TIMEOUT,
                 redirect_timeout=SELENIUM_REDIRECT_TIMEOUT):
        self.chromedriver_path = chromedriver_path
        self.element_timeout = element_timeout
        self.redirect_timeout = redirect_timeout
        self.uder_id = tenant_credentials.get("uder_id") # NOTE: Typo kept
        self.pws = tenant_credentials.get("pws")
        self.api_key = tenant_credentials.get("api_key")
        self.api_secret = tenant_credentials.get("api_secret")
        self.totp_key = tenant_credentials.get("totp_key")
        self.account_id = tenant_credentials.get("account_id")
        if self.api_key not in auth_url: self.auth_url = f"{auth_url}{self.api_key}"
        else: self.auth_url = auth_url

    def _initialize_driver(self):
        abs_path = os.path.abspath(self.chromedriver_path)
        logger.debug(f"Checking for ChromeDriver at: {abs_path}")
        if not os.path.isfile(abs_path):
            raise FileNotFoundError(f"ChromeDriver not found at path: {abs_path}.")
        options = Options()
        # options.add_argument("--headless") # Keep commented for easier debugging
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--blink-settings=imagesEnabled=false")
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--allow-running-insecure-content')
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        service = Service(abs_path)
        try:
            driver = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(60) # Increased page load timeout
            logger.info("WebDriver initialized successfully.")
            return driver
        except WebDriverException as e:
             logger.error(f"Failed to initialize WebDriver: {e}")
             raise AuthenticationError(f"WebDriver initialization failed: {e}") from e

    def _interact_with_element(self, driver, by, value, action, keys_to_send=None, max_retries=SELENIUM_INTERACTION_RETRIES):
        for attempt in range(max_retries):
            try:
                wait = WebDriverWait(driver, self.element_timeout)
                element = wait.until(EC.presence_of_element_located((by, value)))
                if action in ["click", "send_keys", "clear"]: element = wait.until(EC.element_to_be_clickable((by, value)))
                if action == "click": element.click()
                elif action == "clear": element.clear(); time.sleep(0.1)
                elif action == "send_keys":
                    if keys_to_send is not None: element.send_keys(keys_to_send); time.sleep(0.1)
                else: raise ValueError(f"Invalid action: {action}")
                logger.debug(f"Successfully performed '{action}' on element {by}='{value}'")
                return True
            except StaleElementReferenceException:
                logger.warning(f"StaleElementReferenceException on attempt {attempt + 1}/{max_retries} for {by}='{value}'. Retrying...")
                if attempt == max_retries - 1: logger.error(f"Failed interact {by}='{value}' after {max_retries} attempts (staleness)."); raise
                time.sleep(SELENIUM_INTERACTION_RETRY_DELAY * (attempt + 1))
            except TimeoutException: logger.error(f"Timeout waiting for element {by}='{value}' presence/clickability."); raise
            except Exception as e: logger.error(f"Unexpected error interacting with element {by}='{value}': {e}"); raise

    def authenticate(self):
        driver = None # Initialize driver to None
        try:
            driver = self._initialize_driver()
            logger.info(f"Navigating to FlatTrade auth URL for API key {self.api_key}")
            driver.get(self.auth_url)
            logger.info(f"Navigation complete for API key {self.api_key}")

            # --- User ID ---
            logger.info("Locating and interacting with User ID field...")
            self._interact_with_element(driver, By.ID, 'input-19', 'clear')
            self._interact_with_element(driver, By.ID, 'input-19', 'send_keys', keys_to_send=self.uder_id)
            logger.info("Entered user ID.")

            # --- Password ---
            logger.info("Locating and interacting with Password field...")
            self._interact_with_element(driver, By.ID, 'pwd', 'clear')
            self._interact_with_element(driver, By.ID, 'pwd', 'send_keys', keys_to_send=self.pws)
            logger.info("Entered password.")

            # --- Submit Login ---
            try:
                submit_button_xpath = "//form//button[@type='submit'] | //button[contains(., 'Login')] | //button[contains(., 'Submit')]"
                logger.info("Attempting to click initial submit/login button...")
                self._interact_with_element(driver, By.XPATH, submit_button_xpath, 'click')
                logger.info("Clicked initial submit/login button.")
                time.sleep(1.5) # Wait slightly longer for potential transition
            except Exception as e:
                 logger.warning(f"Could not find or click initial submit button ({e}). Proceeding to OTP step.")
                 time.sleep(0.5)

            # --- OTP ---
            logger.info("Locating and interacting with OTP field...")
            otp_field_id = 'pan'
            otp = pyotp.TOTP(self.totp_key).now()
            self._interact_with_element(driver, By.ID, otp_field_id, 'clear')
            self._interact_with_element(driver, By.ID, otp_field_id, 'send_keys', keys_to_send=otp)
            logger.info(f"Entered OTP: {otp}")

            # --- Final Login Button Click ---
            logger.info("Locating and clicking final Login button...")
            login_button_found = False
            try:
                if self._interact_with_element(driver, By.XPATH, "//span[contains(text(),'Login')]", 'click'): login_button_found = True
            except Exception as e1:
                 logger.warning(f"Primary login button locator failed: {e1}. Trying alternative...")
                 try:
                     if self._interact_with_element(driver, By.CSS_SELECTOR, "button.v-btn--is-elevated", 'click'): login_button_found = True
                 except Exception as e2:
                     logger.error(f"Alternative login button locator also failed: {e2}.")
                     raise AuthenticationError("Could not find or click the final Login button.")
            if not login_button_found: raise AuthenticationError("Login button click action did not complete.")
            logger.info("Clicked on final Login button.")

            # --- Wait for Redirect URL & Extract Code ---
            auth_code = None
            current_url_final = None
            try:
                code_pattern_regex = r'.*[?&;#]code=[^&#]+.*'
                logger.info(f"Waiting up to {self.redirect_timeout} seconds for URL matching regex: '{code_pattern_regex}'...")
                redirect_wait = WebDriverWait(driver, self.redirect_timeout)
                redirect_wait.until(EC.url_matches(code_pattern_regex))
                time.sleep(1.0) # Extra wait for JS/redirect stability
                current_url_final = driver.current_url
                logger.info(f"Redirect URL condition met. Final URL: {current_url_final}")

                logger.info("Attempting to extract auth code using regex...")
                match = re.search(r"[?&;#]code=([^&#]+)", current_url_final)
                if match: auth_code = match.group(1); logger.info(f"Auth code extracted via regex: {auth_code}")
                else:
                    logger.warning("Regex failed. Attempting urllib fallback...")
                    try:
                        parsed_url = urlparse(current_url_final)
                        query_params = parse_qs(parsed_url.query)
                        fragment_params = parse_qs(parsed_url.fragment)
                        if 'code' in query_params and query_params['code']: auth_code = query_params['code'][0]; logger.info(f"Auth code via urllib (query): {auth_code}")
                        elif 'code' in fragment_params and fragment_params['code']: auth_code = fragment_params['code'][0]; logger.info(f"Auth code via urllib (fragment): {auth_code}")
                    except Exception as parse_err: logger.error(f"Urllib parsing fallback failed: {parse_err}")

                if not auth_code: raise AuthenticationError(f"Could not extract non-empty auth code from URL: {current_url_final}")

            except TimeoutException:
                last_url = "N/A"; page_source_snippet = "N/A"
                try:
                    last_url = driver.current_url
                    page_source_snippet = driver.page_source[:1000]
                    screenshot_path = f"auth_timeout_tenant_{self.uder_id}_{datetime.now():%Y%m%d_%H%M%S}.png"
                    driver.save_screenshot(screenshot_path)
                    logger.error(f"Timeout! URL matching code pattern not found after {self.redirect_timeout}s. Last URL: {last_url}. Screenshot: {screenshot_path}. Source snippet: {page_source_snippet}...")
                except Exception as diag_err: logger.error(f"Could not capture full diagnostic info on timeout: {diag_err}")
                raise AuthenticationError("Authorization code URL pattern not found after login (timeout).")

            # --- Generate API Signature and Request Token ---
            signature_payload = f"{self.api_key}{auth_code}{self.api_secret}"
            api_signature = hashlib.sha256(signature_payload.encode()).hexdigest()
            logger.info("API signature generated.")
            token_response = requests.post(
                'https://authapi.flattrade.in/trade/apitoken',
                json={'api_key': self.api_key, 'request_code': auth_code, 'api_secret': api_signature},
                timeout=30
            )
            token_response.raise_for_status()
            token_data = token_response.json()
            session_token = token_data.get('token')
            if not session_token: raise AuthenticationError(f"Session token not found/empty in API response: {token_data}")
            logger.info("Session token retrieved successfully.")
            return session_token

        except (WebDriverException, AuthenticationError, requests.exceptions.RequestException) as e:
            logger.error(f"Authentication process failed for tenant {self.uder_id}. Error: {type(e).__name__}: {e}")
            if not isinstance(e, (AuthenticationError, requests.exceptions.RequestException, TimeoutException, FileNotFoundError)): logger.error(traceback.format_exc())
            raise AuthenticationError(f"Authentication failed: {str(e)}") from e
        except Exception as e:
             logger.error(f"Unexpected error during authentication for tenant {self.uder_id}: {e}", exc_info=True)
             raise AuthenticationError(f"Unexpected authentication error: {str(e)}") from e
        finally:
            if driver:
                try: driver.quit(); logger.info("WebDriver closed.")
                except Exception as e: logger.warning(f"Error closing WebDriver: {e}")

# -------------------- Database Operations (Modified for Dependency Injection) --------------------
def get_tenant_by_id(db: Session, tenant_id: str) -> Optional[Tenant]:
    """Retrieve a single tenant by tenant_id using the provided session."""
    return db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()

def get_all_tenants(db: Session) -> List[Tenant]:
    """Retrieve all tenants from the database using the provided session."""
    try:
        tenants = db.query(Tenant).all()
        return tenants
    except Exception as e:
        logger.error(f"Error retrieving tenants: {str(e)}", exc_info=True)
        return [] # Return empty list on error

def update_tenant_auth_token(db: Session, tenant_id: str, new_token: str):
    """Update tenant's authtoken and updated_at timestamp using the provided session."""
    try:
        tenant = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
        if tenant:
            tenant.authtoken = new_token
            tenant.updated_at = datetime.now(timezone.utc) # Use timezone aware
            db.commit()
            logger.info(f"Updated tenant {tenant_id} with new authtoken.")
            return True
        else:
            logger.error(f"Tenant {tenant_id} not found for token update.")
            return False
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating tenant {tenant_id}: {str(e)}", exc_info=True)
        raise # Re-raise to signal failure

def add_tenant_to_db(db: Session, tenant_data: dict) -> Tenant:
    """Adds a new tenant to the database using the provided session."""
    required_fields = ["tenant_id", "uder_id", "pws", "api_key", "api_secret", "totp_key", "account_id"]
    missing = [f for f in required_fields if not tenant_data.get(f)]
    if missing: raise ValueError(f"Missing required fields: {', '.join(missing)}")

    if get_tenant_by_id(db, tenant_data["tenant_id"]):
        raise ValueError(f"Tenant ID '{tenant_data['tenant_id']}' already exists.")

    try:
        encrypted_password = encrypt_password(tenant_data["pws"])
        tenant_model_data = {k: v for k, v in tenant_data.items() if k != "pws"}
        tenant_model_data["encrypted_password"] = encrypted_password

        if "default_qty" in tenant_model_data and tenant_model_data["default_qty"]:
            try: tenant_model_data["default_qty"] = int(tenant_model_data["default_qty"])
            except (ValueError, TypeError):
                 logger.warning(f"Invalid default_qty '{tenant_model_data['default_qty']}' for tenant {tenant_data['tenant_id']}. Setting to None.")
                 tenant_model_data["default_qty"] = None
        else:
            tenant_model_data["default_qty"] = None # Ensure it's None if not provided or empty

        new_tenant = Tenant(**tenant_model_data)
        db.add(new_tenant)
        db.commit()
        db.refresh(new_tenant) # Refresh to get updated state like ID, default dates
        logger.info(f"Added new tenant: {tenant_data['tenant_id']}")
        return new_tenant
    except Exception as e:
        db.rollback()
        logger.error(f"Error adding tenant {tenant_data.get('tenant_id', 'N/A')}: {str(e)}", exc_info=True)
        # Check for specific constraint errors if needed, otherwise re-raise
        raise ValueError(f"Database error adding tenant: {str(e)}") from e

def delete_tenant_from_db(db: Session, tenant_id: str) -> bool:
    """Deletes a tenant from the database by tenant_id using the provided session."""
    try:
        tenant = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
        if tenant:
            db.delete(tenant)
            db.commit()
            logger.info(f"Deleted tenant: {tenant_id}")
            return True
        else:
            logger.warning(f"Tenant {tenant_id} not found for deletion.")
            return False
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting tenant {tenant_id}: {str(e)}", exc_info=True)
        return False

# -------------------- Tenant Authentication Logic (Modified for Dependency Injection) --------------------
def authenticate_tenant_db(db: Session, tenant: Tenant) -> str:
    """Authenticate a single tenant and update DB using the provided session. Uses internal retries."""
    decrypted_password = None
    try:
        decrypted_password = decrypt_password(tenant.encrypted_password)
    except Exception as e:
         logger.error(f"Failed to decrypt password for tenant {tenant.tenant_id}: {e}. Cannot authenticate.")
         raise AuthenticationError(f"Password decryption failed for tenant {tenant.tenant_id}.") from e

    for attempt in range(AUTH_RETRY_COUNT):
        try:
            logger.info(f"Authenticating tenant {tenant.tenant_id} (attempt {attempt+1}/{AUTH_RETRY_COUNT})...")
            tenant_creds = {
                "uder_id": tenant.uder_id, "pws": decrypted_password, "api_key": tenant.api_key,
                "api_secret": tenant.api_secret, "totp_key": tenant.totp_key, "account_id": tenant.account_id
            }
            auth = Authenticator(CHROMEDRIVER_PATH, AUTH_URL, tenant_creds)
            token = auth.authenticate()
            # Pass the db session to update function
            update_tenant_auth_token(db, tenant.tenant_id, token)
            logger.info(f"Tenant {tenant.tenant_id} authenticated successfully on attempt {attempt+1}.")
            return token
        except AuthenticationError as e:
            logger.error(f"Auth attempt {attempt+1} failed for {tenant.tenant_id}: {str(e)}")
            if attempt < AUTH_RETRY_COUNT - 1: time.sleep(AUTH_RETRY_DELAY)
            else: logger.error(f"All {AUTH_RETRY_COUNT} auth attempts failed for {tenant.tenant_id}"); raise
        except Exception as e:
             logger.error(f"Unexpected error during auth setup/call for {tenant.tenant_id} (attempt {attempt+1}): {e}", exc_info=True)
             if attempt < AUTH_RETRY_COUNT - 1: time.sleep(AUTH_RETRY_DELAY)
             else: logger.error(f"All {AUTH_RETRY_COUNT} auth attempts failed for {tenant.tenant_id} due to unexpected error."); raise AuthenticationError(f"Unexpected final error for {tenant.tenant_id}: {e}") from e
    # Should not be reached if raise works correctly, but added for safety
    raise AuthenticationError(f"Authentication failed for tenant {tenant.tenant_id} after all retries.")


def periodic_authentication():
    """Background thread task for periodic re-authentication. Uses its own DB session scope."""
    initial_delay = 30 # seconds
    auth_interval = 24 * 60 * 60 # seconds (24 Hours)
    error_retry_interval = 5 * 60 # seconds (5 minutes)

    logger.info(f"Periodic authentication thread started. First run in {initial_delay}s, then every {auth_interval / 3600:.1f} hrs.")
    time.sleep(initial_delay)

    while True:
        next_run_in = auth_interval
        # Use a context manager for session handling within the loop
        try:
            with SessionLocal() as db: # Creates a new session for this cycle
                logger.info("Starting periodic re-authentication cycle.")
                tenants = get_all_tenants(db) # Use the cycle-specific session
                if not tenants:
                    logger.info("No tenants found for periodic auth.")
                else:
                    success_count, failure_count = 0, 0
                    for tenant in tenants:
                        logger.info(f"Attempting periodic re-auth for {tenant.tenant_id}...")
                        try:
                            # Pass the cycle-specific session to the auth function
                            authenticate_tenant_db(db, tenant)
                            success_count += 1
                        except Exception as e: # Catch errors from authenticate_tenant_db
                            # Error already logged within the function on final failure
                            failure_count += 1
                    logger.info(f"Periodic re-auth cycle complete. Success: {success_count}, Failures: {failure_count}.")
        except Exception as e:
            logger.error(f"Critical error in periodic authentication main loop: {str(e)}", exc_info=True)
            next_run_in = error_retry_interval
            logger.info(f"Sleeping for {next_run_in / 60} minutes after critical error.")
        # Session is automatically closed by the 'with' statement here, even on error

        logger.info(f"Periodic authentication thread sleeping for {next_run_in / 3600:.1f} hrs.")
        time.sleep(next_run_in)

# -------------------- Order Placement Logic (Consistent, uses shared executor) --------------------
# Use a shared executor instance, initialized later in lifespan
order_executor: Optional[ThreadPoolExecutor] = None

def place_order_for_tenant(tenant: Tenant, payload: dict) -> dict:
    """Place order for a tenant. Assumes tenant object is passed with valid token."""
    start_time = time.time()
    result = {"tenant_id": tenant.tenant_id, "status": "failure", "error": None, "response": None}
    try:
        uid = payload.get("uid", tenant.uder_id)
        actid = payload.get("actid", tenant.account_id)
        exch = payload.get("exch", DEFAULT_EXCHANGE)
        tsym = payload.get("symbol")
        if not tsym: raise ValueError("Missing required 'symbol'.")

        qty_str = payload.get("quantity")
        if not qty_str:
             qty_val = getattr(tenant, "default_qty", None)
             if qty_val is not None and qty_val > 0: qty_str = str(qty_val)
             else: raise ValueError("Missing 'quantity' and no valid default quantity set.")
        try:
            if int(qty_str) <= 0: raise ValueError("Quantity must be positive.")
        except (ValueError, TypeError): raise ValueError(f"Invalid quantity '{qty_str}'.")

        prc = str(payload.get("price", "0.0"))
        prd = payload.get("prd", "M")
        action = payload.get("action", "").strip().lower()
        if action == "buy": trantype = "B"
        elif action == "sell": trantype = "S"
        else: raise ValueError("Invalid action. Must be 'buy' or 'sell'.")

        prctyp = payload.get("prctyp", "MKT")
        retention = payload.get("retention", DEFAULT_RETENTION)
        remarks = payload.get("remarks", DEFAULT_REMARKS)

        inner_payload = {
            "uid": str(uid), "actid": str(actid), "exch": str(exch), "tsym": str(tsym),
            "qty": str(qty_str), "prc": prc, "prd": str(prd), "trantype": trantype,
            "prctyp": str(prctyp), "ret": str(retention), "remarks": str(remarks)
        }

        if not tenant.authtoken: raise ValueError(f"Tenant {tenant.tenant_id} has no authtoken.")

        payload_str = f"jData={json.dumps(inner_payload)}&jKey={tenant.authtoken}"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        logger.info(f"Placing order for {tenant.tenant_id}: {inner_payload}")

        response = requests.post(PLACE_ORDER_ENDPOINT, headers=headers, data=payload_str, timeout=15) # Increased timeout slightly
        logger.debug(f"Tenant {tenant.tenant_id} - Resp Status: {response.status_code}, Text: {response.text[:200]}...")
        response.raise_for_status()
        response_json = response.json()
        logger.info(f"Order response for {tenant.tenant_id}: {response_json}")

        if isinstance(response_json, dict) and response_json.get("stat") == "Ok":
             result["status"] = "success"; result["response"] = response_json
             logger.info(f"Order placed successfully for {tenant.tenant_id}.")
        elif isinstance(response_json, dict) and response_json.get("stat") == "Not_Ok":
             err_msg = response_json.get("emsg", "Unknown API error.")
             result["status"] = "failure"; result["error"] = f"API Error: {err_msg}"; result["response"] = response_json
             logger.error(f"Order failed for {tenant.tenant_id}. API Error: {err_msg}")
        else:
             result["status"] = "failure"; result["error"] = f"Unexpected API response format: {str(response_json)[:200]}..."
             logger.error(f"Order failed for {tenant.tenant_id} due to unexpected API response format.")

    except requests.exceptions.Timeout: logger.error(f"Order failed for {tenant.tenant_id}: Request timed out."); result["error"] = "Request timed out"
    except requests.exceptions.RequestException as e:
        error_text = str(e); status_code = "N/A"; resp_text = "N/A"
        if hasattr(e, "response") and e.response is not None: status_code=e.response.status_code; resp_text=e.response.text[:200]
        logger.error(f"Order failed for {tenant.tenant_id} (RequestException): {error_text} | Status: {status_code}, Response: {resp_text}...")
        result["error"] = f"Network/Request Error: {error_text}"
    except ValueError as e: logger.error(f"Order failed for {tenant.tenant_id} (Input/State Error): {str(e)}"); result["error"] = f"Input/State Error: {str(e)}"
    except Exception as e: logger.error(f"Unexpected error placing order for {tenant.tenant_id}: {str(e)}", exc_info=True); result["error"] = f"Unexpected Error: {str(e)}"
    finally:
        duration = time.time() - start_time
        logger.info(f"Order placement attempt for {tenant.tenant_id} took {duration:.2f}s. Status: {result['status']}")
        return result

async def process_orders_for_all_tenants(db: Session, payload: dict) -> list:
    """Process concurrent order placement for all active tenants using the provided session."""
    if order_executor is None:
        logger.error("Order executor not initialized. Cannot process orders.")
        raise RuntimeError("Order executor is not available.")

    tenants = get_all_tenants(db) # Use the passed DB session
    if not tenants: logger.warning("Webhook received but no tenants found."); return []

    loop = asyncio.get_event_loop()
    tasks, valid_tenants = [], []
    logger.info(f"Processing order payload for {len(tenants)} potential tenants.")

    for tenant in tenants:
        if not tenant.authtoken:
            logger.warning(f"Skipping {tenant.tenant_id}: No authtoken.")
            continue
        # Pass a copy of the tenant object and payload
        task = loop.run_in_executor(order_executor, place_order_for_tenant, tenant, payload.copy())
        tasks.append(task); valid_tenants.append(tenant)

    if not tasks: logger.warning("No valid tenants with authtokens found."); return []

    logger.info(f"Awaiting results for {len(tasks)} order placement tasks...")
    results = await asyncio.gather(*tasks, return_exceptions=True)
    logger.info("All order placement tasks completed.")

    processed_results = []
    for i, res in enumerate(results):
        tenant_id = valid_tenants[i].tenant_id
        if isinstance(res, Exception):
            logger.error(f"Exception during order task for {tenant_id}: {str(res)}", exc_info=isinstance(res, (ValueError, TypeError))) # Log trace for unexpected
            processed_results.append({"tenant_id": tenant_id, "status": "failure", "error": f"Task Error: {str(res)}"})
        elif isinstance(res, dict): processed_results.append(res)
        else:
             logger.error(f"Unexpected result type for {tenant_id}: {type(res)} - {res}")
             processed_results.append({"tenant_id": tenant_id, "status": "failure", "error": f"Unexpected task result type: {type(res)}"})
    return processed_results


# -------------------- Lifespan Event Handler (From Script 1) --------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup Logic ---
    global order_executor
    logger.info("Server startup: Initializing...")

    # Initialize thread pool for orders
    order_executor = ThreadPoolExecutor(max_workers=ORDER_EXEC_MAX_WORKERS, thread_name_prefix="OrderExec")
    logger.info(f"Order executor initialized with max_workers={ORDER_EXEC_MAX_WORKERS}")

    # Start the periodic auth thread in the background
    start_auth_thread()

    # Perform initial auth check for tenants without tokens concurrently
    logger.info("Checking for tenants needing initial authentication...")
    initial_auth_tasks = []
    loop = asyncio.get_event_loop()

    try:
        # Use a Session context for the initial check
        with SessionLocal() as db:
            tenants_needing_auth = [t for t in get_all_tenants(db) if not t.authtoken]
            logger.info(f"Found {len(tenants_needing_auth)} tenants potentially needing initial auth.")

            # Use a ThreadPoolExecutor for blocking Selenium tasks during startup
            with ThreadPoolExecutor(max_workers=INITIAL_AUTH_MAX_WORKERS, thread_name_prefix="InitialAuth") as initial_auth_executor:
                for tenant in tenants_needing_auth:
                    logger.info(f"Queueing initial auth for {tenant.tenant_id}")
                    # Each thread task needs its own DB session
                    task = loop.run_in_executor(initial_auth_executor, lambda t=tenant: authenticate_tenant_db(SessionLocal(), t))
                    initial_auth_tasks.append(task)

        if initial_auth_tasks:
            logger.info(f"Waiting for {len(initial_auth_tasks)} initial authentications...")
            results = await asyncio.gather(*initial_auth_tasks, return_exceptions=True)
            success_count = sum(1 for r in results if isinstance(r, str)) # Successful auth returns token string
            fail_count = len(results) - success_count
            logger.info(f"Initial authentication phase complete. Success: {success_count}, Failures: {fail_count}. Failures retry periodically.")
        else:
            logger.info("No tenants required initial authentication.")

    except Exception as e:
        logger.critical(f"Error during initial authentication phase: {e}", exc_info=True)
        # Log critical and continue startup

    logger.info("Server startup initialization complete. Application ready.")

    yield # Application runs here

    # --- Shutdown Logic ---
    logger.info("Server shutdown: Cleaning up resources...")
    if order_executor:
        logger.info("Shutting down order executor...")
        order_executor.shutdown(wait=True)
        logger.info("Order executor shut down.")
    # Periodic auth thread is daemon, will exit automatically
    logger.info("Server shutdown complete.")


# -------------------- FastAPI Application Setup --------------------
app = FastAPI(
    title="FlatTrade Multi-Tenant API (Admin Enabled)", # Updated title
    version="1.2.0", # Incremented version
    lifespan=lifespan # Use the lifespan handler
)

# --- CORS Middleware (From Script 1) ---
origins = [
    "http://localhost:5173", # Example frontend dev server
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    # Add any production frontend origins here
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Admin Auth & JWT Utilities (From Script 1) --------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin/login")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_admin_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None or username != ADMIN_USERNAME:
            logger.warning(f"JWT validation failed: username mismatch or missing. Token sub: {username}")
            raise credentials_exception
        # Return the validated username for potential logging/auditing
        return username
    except JWTError as e:
        logger.warning(f"JWT Error during decoding: {e}")
        raise credentials_exception
    except Exception as e:
        logger.error(f"Unexpected error during JWT validation: {e}", exc_info=True)
        raise credentials_exception

# -------------------- Public Endpoints --------------------

@app.post("/webhook")
async def webhook_endpoint(request: Request, db: Session = Depends(get_db)):
    """Public endpoint for receiving trading signals. Uses DB session dependency."""
    try:
        payload = await request.json()
        logger.info(f"Webhook received: {json.dumps(payload)}")

        symbol = payload.get("symbol")
        action = payload.get("action", "").strip().lower()
        if not symbol or action not in ["buy", "sell"]:
             logger.error(f"Invalid webhook: Missing/invalid 'symbol' or 'action'. Payload: {payload}")
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing or invalid 'symbol' or 'action'.")

        if not payload.get("execute", False):
            logger.info("Webhook skipped: Execution flag not set.")
            return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "skipped", "message": "Execution flag not set."})

        logger.info(f"Webhook processing orders for {symbol} ({action})...")
        # Pass the DB session to the processing function
        results = await process_orders_for_all_tenants(db, payload)

        num_ok = sum(1 for r in results if r.get('status') == 'success')
        num_err = len(results) - num_ok
        if not results: overall_status = "no_tenants"
        elif num_err == 0: overall_status = "success"
        elif num_ok > 0: overall_status = "partial_success"
        else: overall_status = "failure"

        http_status = status.HTTP_207_MULTI_STATUS if overall_status == "partial_success" else status.HTTP_200_OK

        return JSONResponse(status_code=http_status, content={"status": overall_status, "data": results})

    except json.JSONDecodeError:
        logger.error("Invalid JSON in webhook payload")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload")
    except HTTPException as e: raise e # Re-raise FastAPI HTTP exceptions
    except Exception as exc:
        logger.exception(f"Error processing webhook: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal server error: {exc}")

@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint. Uses DB session dependency."""
    db_ok = False
    db_error = None
    try:
        # Use the injected session to perform a query
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        logger.warning(f"Health check DB connection/query failed: {e}")
        db_error = str(e)

    return {
        "status": "healthy" if db_ok else "unhealthy",
        "timestamp": datetime.now(timezone.utc).isoformat(), # Use timezone aware
        "database_connected": db_ok,
        "database_error": db_error if not db_ok else None
    }

# -------------------- Admin Endpoints (From Script 1) --------------------

@app.post("/admin/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Admin login endpoint. Uses form data (username, password)."""
    logger.info(f"Admin login attempt for user: {form_data.username}")
    # **Plain text password comparison as requested**
    if form_data.username == ADMIN_USERNAME and form_data.password == ADMIN_PASSWORD:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": ADMIN_USERNAME}, expires_delta=access_token_expires
        )
        logger.info(f"Admin login successful for user: {form_data.username}")
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        logger.warning(f"Admin login failed for user: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

# --- Pydantic models for Admin responses (From Script 1) ---
class LogEntry(BaseModel):
    timestamp: str
    level: str
    thread: str
    message: str
    raw: str

class TenantStatus(BaseModel):
    tenant_id: str
    # Use alias to map DB field 'uder_id' to Pydantic field 'user_id'
    user_id: str = Field(..., alias="uder_id")
    # Use alias to map DB field 'updated_at' to Pydantic field 'last_updated'
    last_updated: Optional[datetime] = Field(None, alias="updated_at")
    has_token: bool

    class Config:
        from_attributes = True # Pydantic V2+ config for ORM mode
        populate_by_name = True # Allow population by alias name

class TenantCreate(BaseModel):
    tenant_id: str
    uder_id: str # Typo kept for consistency with DB model during creation
    pws: str # Plain password received from admin
    api_key: str
    api_secret: str
    totp_key: str
    account_id: str
    default_qty: Optional[int] = None

class TenantBasicInfo(BaseModel):
    tenant_id: str
    uder_id: str # Typo kept for response consistency
    account_id: str
    default_qty: Optional[int] = None
    updated_at: Optional[datetime] = None # Keep original field name for response

    class Config:
        from_attributes = True # Pydantic V2+ config for ORM mode

# --- Admin API Endpoints (From Script 1, using Depends(get_db) and Depends(get_current_admin_user)) ---

@app.get("/admin/logs", response_model=List[LogEntry])
async def get_admin_logs(limit: Optional[int] = 100, current_admin: str = Depends(get_current_admin_user)):
    """(Admin) Get the latest log entries."""
    logger.info(f"Admin '{current_admin}' requested logs (limit: {limit}).")
    log_file = Path(LOG_FILE_NAME)
    if not log_file.is_file():
        logger.warning(f"Log file '{LOG_FILE_NAME}' not found.")
        return []

    lines = []
    try:
        # Read last N lines efficiently if possible, otherwise read all and slice
        # Simple approach: read all, take last N
        with open(log_file, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            lines = all_lines[-limit:]
    except Exception as e:
        logger.error(f"Error reading log file '{LOG_FILE_NAME}': {e}")
        raise HTTPException(status_code=500, detail="Could not read log file.")

    parsed_logs = []
    # Regex to parse log lines (adjust if format changes)
    log_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+):([^:]+):\s+(.*)")
    for line in lines:
        line = line.strip()
        match = log_pattern.match(line)
        if match:
            parsed_logs.append(LogEntry(
                timestamp=match.group(1), level=match.group(2),
                thread=match.group(3), message=match.group(4).strip(), raw=line
            ))
        elif line: # Append non-matching lines as raw entries
             parsed_logs.append(LogEntry(timestamp="", level="RAW", thread="", message=line, raw=line))
    return parsed_logs

@app.get("/admin/auth-status", response_model=List[TenantStatus])
async def get_admin_auth_status(db: Session = Depends(get_db), current_admin: str = Depends(get_current_admin_user)):
    """(Admin) Get authentication status for all tenants."""
    logger.info(f"Admin '{current_admin}' requested auth status for all tenants.")
    tenants = get_all_tenants(db)
    status_list = []
    for tenant in tenants:
        try:
            # --- FIX START ---
            # 1. Calculate the required value BEFORE creating the Pydantic model
            has_token_value = bool(tenant.authtoken)

            # 2. Create the Pydantic model instance manually, providing all required fields explicitly
            #    Map the source attributes (tenant.*) to the Pydantic model fields.
            status_item = TenantStatus(
                tenant_id=tenant.tenant_id,
                user_id=tenant.uder_id,      # Map DB 'uder_id' to Pydantic 'user_id'
                last_updated=tenant.updated_at, # Map DB 'updated_at' to Pydantic 'last_updated'
                has_token=has_token_value   # Provide the calculated value for 'has_token'
            )
            # --- FIX END ---

            status_list.append(status_item)
        except Exception as e:
            # Log error if validation/creation fails for a specific tenant
            logger.error(f"Error processing tenant {tenant.tenant_id} for status display: {e}", exc_info=True)
            # Optionally append a placeholder or skip this tenant
            # Example placeholder:
            # status_list.append(TenantStatus(tenant_id=tenant.tenant_id, user_id="Error", last_updated=None, has_token=False))

    return status_list
@app.post("/admin/tenants", response_model=TenantBasicInfo, status_code=status.HTTP_201_CREATED)
async def admin_add_tenant(tenant_data: TenantCreate, db: Session = Depends(get_db), current_admin: str = Depends(get_current_admin_user)):
    """(Admin) Add a new tenant."""
    logger.info(f"Admin '{current_admin}' attempting to add tenant: {tenant_data.tenant_id}")
    try:
        tenant_dict = tenant_data.model_dump() # Use model_dump in Pydantic v2+
        new_tenant = add_tenant_to_db(db, tenant_dict)
        logger.info(f"Admin '{current_admin}' successfully added tenant: {new_tenant.tenant_id}")
        # Use model_validate (Pydantic V2+) for response model
        return TenantBasicInfo.model_validate(new_tenant)
    except ValueError as e:
        logger.error(f"Admin add tenant failed for {tenant_data.tenant_id}: {str(e)}")
        status_code = status.HTTP_409_CONFLICT if "already exists" in str(e).lower() else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error adding tenant {tenant_data.tenant_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error adding tenant.")

@app.delete("/admin/tenants/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_delete_tenant(tenant_id: str, db: Session = Depends(get_db), current_admin: str = Depends(get_current_admin_user)):
    """(Admin) Delete a tenant."""
    logger.info(f"Admin '{current_admin}' attempting to delete tenant: {tenant_id}")
    deleted = delete_tenant_from_db(db, tenant_id)
    if not deleted:
        logger.warning(f"Admin delete failed: Tenant {tenant_id} not found or error occurred.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' not found or could not be deleted.")
    logger.info(f"Admin '{current_admin}' successfully deleted tenant: {tenant_id}")
    # No content needed for HTTP 204 response
    return None

@app.post("/admin/tenants/{tenant_id}/reauthenticate", response_model=Dict[str, Any])
async def admin_reauthenticate_tenant(tenant_id: str, db: Session = Depends(get_db), current_admin: str = Depends(get_current_admin_user)):
    """(Admin) Manually trigger re-authentication for a specific tenant (runs in background)."""
    logger.info(f"Admin '{current_admin}' triggered re-auth for tenant: {tenant_id}")
    tenant = get_tenant_by_id(db, tenant_id)
    if not tenant:
        logger.error(f"Re-auth failed: Tenant {tenant_id} not found.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' not found.")

    if order_executor is None:
         logger.error("Executor not available for re-authentication task.")
         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server configuration error: executor not available.")

    try:
        # Run the authentication in a separate thread using the executor.
        # Requires a new DB session for the thread.
        loop = asyncio.get_event_loop()
        # Use lambda to pass the tenant object correctly to the executor function
        # Pass a *new* SessionLocal() instance to the function running in the thread
        token = await loop.run_in_executor(order_executor, lambda t=tenant: authenticate_tenant_db(SessionLocal(), t))
        logger.info(f"Admin-triggered re-auth successful for tenant: {tenant_id}")
        return {"status": "success", "message": f"Tenant {tenant_id} re-authenticated successfully."}
    except AuthenticationError as e:
        logger.error(f"Admin-triggered re-auth failed for tenant {tenant_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, # 500 indicates failure in the process
            detail=f"Authentication failed for {tenant_id}: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error during admin re-auth trigger for {tenant_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected server error triggering re-authentication for {tenant_id}."
        )

@app.post("/admin/tenants/reauthenticate-all", response_model=Dict[str, Any])
async def admin_reauthenticate_all_tenants(db: Session = Depends(get_db), current_admin: str = Depends(get_current_admin_user)):
    """(Admin) Manually trigger re-authentication for ALL tenants (runs in background)."""
    logger.info(f"Admin '{current_admin}' triggered re-auth for ALL tenants.")
    tenants = get_all_tenants(db) # Get tenants using request session
    if not tenants:
        return {"status": "skipped", "message": "No tenants found to re-authenticate."}

    if order_executor is None:
        logger.error("Executor not available for re-authenticate-all task.")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server configuration error: executor not available.")

    # Define the task to be run in the background thread
    def run_all_auths_sync():
        success_count = 0
        failure_count = 0
        total = len(tenants)
        logger.info(f"Background task starting re-auth for {total} tenants.")
        # Use a new session scope for the entire background task execution
        with SessionLocal() as task_db:
            # Iterate through a *copy* of the tenant list or tenant IDs if needed
            # to avoid issues if the original list is modified elsewhere.
            # Fetching fresh tenant data within the loop might be safer if updates are frequent.
            tenant_ids = [t.tenant_id for t in tenants] # Get IDs first
            for t_id in tenant_ids:
                try:
                    # Fetch the tenant fresh within the task's DB session
                    current_tenant = get_tenant_by_id(task_db, t_id)
                    if not current_tenant:
                        logger.warning(f"Background task: Tenant {t_id} not found during re-auth loop, skipping.")
                        failure_count +=1
                        continue

                    logger.info(f"Background task: Attempting re-auth for {current_tenant.tenant_id}")
                    # Use the task-specific session
                    authenticate_tenant_db(task_db, current_tenant)
                    success_count += 1
                except Exception as e:
                    logger.error(f"Background task: Re-auth failed for {t_id}: {e}")
                    failure_count += 1
        logger.info(f"Background task finished re-auth. Total: {total}, Success: {success_count}, Failed: {failure_count}.")

    # Submit the synchronous function to the executor
    order_executor.submit(run_all_auths_sync)

    logger.info(f"Admin request acknowledged. Re-authentication for {len(tenants)} tenants initiated in the background.")
    return {
        "status": "triggered",
        "message": f"Re-authentication process for {len(tenants)} tenants has been initiated in the background. Check logs for progress."
    }


# -------------------- Server Functions --------------------
def run_server(host="0.0.0.0", port=8080): # Use a common non-privileged port like 8080
    """Run the FastAPI server with uvicorn"""
    logger.info(f"Starting server on {host}:{port}")
    # Use the app instance directly
    uvicorn.run(app, host=host, port=port, reload=False) # reload=False for production

auth_thread_instance: Optional[threading.Thread] = None
def start_auth_thread():
    """Start the periodic authentication in a separate daemon thread."""
    global auth_thread_instance
    if auth_thread_instance and auth_thread_instance.is_alive():
        logger.warning("Authentication thread already running.")
        return auth_thread_instance

    logger.info("Attempting to start periodic authentication thread...")
    auth_thread_instance = threading.Thread(target=periodic_authentication, name="PeriodicAuthThread", daemon=True)
    auth_thread_instance.start()
    if auth_thread_instance.is_alive():
        logger.info("Authentication thread started.")
    else:
        logger.error("Authentication thread failed to start.")
    return auth_thread_instance

# Main execution block (if run directly)
if __name__ == "__main__":
    # The lifespan handler manages startup/shutdown tasks (like starting threads, initializing executors)
    # when run via uvicorn command or programmatically like below.
    run_server()


# --- END OF FILE backend_merged.py ---