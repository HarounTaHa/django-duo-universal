from duo_universal.client import Client, DuoException
from django.conf import settings
import os

class DuoUniversalClient:
    """
    Client for interacting with Duo Universal Prompt
    """

    def __init__(self):
        self.client = Client(
            client_id=settings.DUO_CLIENT_ID,
            client_secret=settings.DUO_CLIENT_SECRET,
            host=settings.DUO_API_HOST,
            redirect_uri=settings.DUO_REDIRECT_URI,
            use_duo_code_attribute=True
        )

    def generate_auth_url(self, username, state=None):
        """
        Generate the authentication URL for the Duo Universal Prompt
        """
        try:
            # If no state is provided, generate a random one
            if not state:
                state =  self.client.generate_state()

            # Generate the auth URL
            auth_url = self.client.create_auth_url(
                username=username,
                state=state
            )

            return {
                'auth_url': auth_url,
                'state': state
            }
        except DuoException as e:
            raise Exception(f"Duo Universal error: {str(e)}")

    def exchange_authorization_code(self, code, username):
        """
        Exchange the authorization code for a token
        """
        try:
            # Exchange the code for a token
            decoded_token = self.client.exchange_authorization_code_for_2fa_result(
                code,
                username=username
            )

            # Verify that the authentication was successful
            return decoded_token is not None
        except DuoException as e:
            raise Exception(f"Duo Universal error: {str(e)}")