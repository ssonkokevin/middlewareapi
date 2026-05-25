"""
Configuration module for the middleware API gateway.
Loads all settings from environment variables / .env file using pydantic-settings.

Each environment (prod / test) has its own URL, credentials, and allowed caller IP
so they can be changed independently without touching the other environment.
"""

import os
from typing import Dict, List, Any
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow",
    )

    # ---------------------------------------------------------- NIRA production
    NIRA_PROD_URL:        str
    NIRA_PROD_USERNAME:   str
    NIRA_PROD_PASSWORD:   str
    NIRA_PROD_ALLOWED_IP: str = "10.20.20.1"

    # ------------------------------------------------------------- NIRA test
    NIRA_TEST_URL:        str
    NIRA_TEST_USERNAME:   str
    NIRA_TEST_PASSWORD:   str
    NIRA_TEST_ALLOWED_IP: str = "10.20.20.4"

    # ------------------------------------------------------- Refugee production
    REFUGEE_PROD_VALIDATE_URL: str
    REFUGEE_PROD_LOGIN_URL:    str
    REFUGEE_PROD_USERNAME:     str
    REFUGEE_PROD_PASSWORD:     str
    REFUGEE_PROD_ALLOWED_IP:   str = "192.168.168.10"

    # ---------------------------------------------------------- Refugee test
    REFUGEE_TEST_VALIDATE_URL: str
    REFUGEE_TEST_LOGIN_URL:    str
    REFUGEE_TEST_USERNAME:     str
    REFUGEE_TEST_PASSWORD:     str
    REFUGEE_TEST_ALLOWED_IP:   str = "192.168.168.12"

    # ---------------------------------------------------------------- Shared
    NIRA_CERT_PATH: str  = "wwwroot/certificates/niragoug.crt"
    TIMEOUT:        int  = 60
    DEBUG:          bool = True

    # --------------------------------------------------------------- Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # ---------------------------------------------------------------- Admin
    ADMIN_SECRET_KEY: str

    # ----------------------------------------------------------- Helper methods

    def get_nira_config(self, env: str) -> Dict[str, str]:
        """
        Return the NIRA URL, credentials, and allowed caller IP for the given env.

        Args:
            env: "prod" or "test"

        Returns:
            dict with keys: url, username, password, allowed_ip
        """
        if env == "prod":
            return {
                "url":        self.NIRA_PROD_URL,
                "username":   self.NIRA_PROD_USERNAME,
                "password":   self.NIRA_PROD_PASSWORD,
                "allowed_ip": self.NIRA_PROD_ALLOWED_IP,
            }
        return {
            "url":        self.NIRA_TEST_URL,
            "username":   self.NIRA_TEST_USERNAME,
            "password":   self.NIRA_TEST_PASSWORD,
            "allowed_ip": self.NIRA_TEST_ALLOWED_IP,
        }

    def get_refugee_config(self, env: str) -> Dict[str, str]:
        """
        Return the Refugee URLs, credentials, and allowed caller IP for the given env.

        Args:
            env: "prod" or "test"

        Returns:
            dict with keys: validate_url, login_url, username, password, allowed_ip
        """
        if env == "prod":
            return {
                "validate_url": self.REFUGEE_PROD_VALIDATE_URL,
                "login_url":    self.REFUGEE_PROD_LOGIN_URL,
                "username":     self.REFUGEE_PROD_USERNAME,
                "password":     self.REFUGEE_PROD_PASSWORD,
                "allowed_ip":   self.REFUGEE_PROD_ALLOWED_IP,
            }
        return {
            "validate_url": self.REFUGEE_TEST_VALIDATE_URL,
            "login_url":    self.REFUGEE_TEST_LOGIN_URL,
            "username":     self.REFUGEE_TEST_USERNAME,
            "password":     self.REFUGEE_TEST_PASSWORD,
            "allowed_ip":   self.REFUGEE_TEST_ALLOWED_IP,
        }

    def get_all_clients(self) -> List[Dict[str, Any]]:
        """
        Return list of all registered clients from environment variables.
        Looks for variables matching pattern: CLIENT_<NAME>_ID and CLIENT_<NAME>_SECRET
        Optionally: CLIENT_<NAME>_NAME and CLIENT_<NAME>_ENV for metadata

        Returns:
            List of client dicts with client_id, client_secret, client_name, allowed_env
        """
        clients = []
        # Check both os.environ (system env) and model_extra (.env file fields)
        all_env_vars = dict(os.environ)
        all_env_vars.update(getattr(self, 'model_extra', {}) or {})

        for key in all_env_vars:
            if key.startswith("CLIENT_") and key.endswith("_ID"):
                prefix = key[:-3]  # Remove _ID suffix
                secret_key = f"{prefix}_SECRET"
                name_key = f"{prefix}_NAME"
                env_key = f"{prefix}_ENV"

                client_id = all_env_vars.get(key, "")
                client_secret = all_env_vars.get(secret_key, "")

                if client_id and client_secret:
                    # Extract readable name from prefix (e.g., CLIENT_KYC_PROD -> kyc_prod)
                    name_prefix = prefix[7:] if prefix.startswith("CLIENT_") else prefix
                    client_name = all_env_vars.get(name_key, name_prefix.replace("_", " ").title())
                    allowed_env = all_env_vars.get(env_key, "both")

                    clients.append({
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "client_name": client_name,
                        "allowed_env": allowed_env,
                    })

        return clients


# Single application-wide settings instance
settings = Settings()
