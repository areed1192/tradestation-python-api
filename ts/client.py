import os
import time
import json

import request
import urllib.parse

from typing import List
from typing import Dict
from typing import Union
from typing import Optional

from datetime import date
from datetime import datetime

from dateutil.parser import parse


class TradeStationClient():

    """
        Tradestation API Client Class.

        Implements OAuth 2.0 Authorization Code Grant workflow, handles configuration
        and state management, adds token for authenticated calls, and performs request 
        to the TD Ameritrade API.
    """

    def __init__(self, username: str, client_id: str, client_secret: str, redirect_uri: str, paper_trading: bool = True) -> None:
        """Initalizes the Tradestation Client object.

        Arguments:
        ----
        username (str): The username of the account.

        client_id (str): The Client ID assigned to you during the App registration. This can
            be found at the app registration portal.

        client_secret (str):  The Client Secret assigned to you during the App registration. This can
            be found at the app registration portal.

        redirect_uri (str): This is the redirect URL that you specified when you created your
            Tradestation Application.

        paper_trading (bool, optional): Specifies whether you want to use the simulation account or not. 
            Defaults to True.

        Usage:
        ----
            >>> tradestation_client = TradeStationClient(
                    username=username,
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                    paper_trading=paper_trading
                )
            >>> tradestation_client
        """

        # define the configuration settings.
        self.config = {
            'client_id': client_id,
            'client_secret': client_secret,
            'username': username,
            'redirect_uri': redirect_uri,
            'resource': 'https://api.tradestation.com',
            'paper_resource': 'https://sim-api.tradestation.com',
            'api_version': 'v2',
            'paper_api_version': 'v2',
            'auth_endpoint': 'https://api.tradestation.com/v2/Security/Authorize',
            'cache_state': True,
            'refresh_enabled': True,
            'paper_trading': paper_trading
        }

        # initalize the client to either use paper trading account or regular account.
        if self.config['paper_trading']:
            self.paper_trading_mode = True
        else:
            self.paper_trading_mode = False

        # call the _state_manager method and update the state to init (initalized)
        self._state_manager('init')

        # define a new attribute called 'authstate' and initalize it to '' (Blank). This will be used by our login function.
        self.authstate = False

    def __repr__(self) -> str:
        """Defines the string representation of our TD Ameritrade Class instance.

        Returns:
        ----
        (str): A string representation of the client.
        """

        # Define the string representation.
        str_representation = '<TradeStation Client (logged_in={log_in}, authorized={auth_state})>'.format(
            log_in=self.state['logged_in'],
            auth_state=self.authstate
        )

        return str_representation

    def headers(self, mode: str = None) -> Dict:
        """Sets the headers for the request.

        Overview:
        ----
        Returns a dictionary of default HTTP headers for calls to TradeStation API,
        in the headers we defined the Authorization and access token.

        Arguments:
        ----
        mode (str): Defines the content-type for the headers dictionary.

        Returns:
        ----
        (dict): The headers dictionary to be used in the request.
        """

        # Grab the Access Token.
        token = self.state['access_token']

        # Create the headers dictionary
        headers = {
            'Authorization': 'Bearer {access_token}'.format(access_token=token)
        }

        # Set the Mode.
        if mode == 'application/json':
            headers['Content-type'] = 'application/json'
        elif mode == 'chunked':
            headers['Transfer-Encoding'] = 'Chunked'

        return headers

    def _api_endpoint(self, url: str) -> str:
        """Creates an API URL.

        Overview:
        ----  
        Convert relative endpoint (e.g., 'quotes') to full API endpoint.

        Arguments:
        ----
        url (str): The URL that needs conversion to a full endpoint URL.

        Returns:
        ---
        (str): A full URL.
        """

        # paper trading uses a different base url compared to regular trading.
        if self.paper_trading_mode:
            full_url = '/'.join([self.config['paper_resource'],
                                 self.config['paper_api_version'], url])
        else:
            full_url = '/'.join([self.config['resource'],
                                 self.config['api_version'], url])

        return full_url

    def _state_manager(self, action: str) -> None:
        """Handles the state.
            Manages the self.state dictionary. Initalize State will set
            the properties to their default value. Save will save the 
            current state if 'cache_state' is set to TRUE.

            NAME: action
            DESC: action argument must of one of the following:
                    'init' -- Initalize State.
                    'save' -- Save the current state.
            TYPE: String            
        """

        # Define the initalized state, these are the default values.
        initialized_state = {
            'access_token': None,
            'refresh_token': None,
            'access_token_expires_at': 0,
            'access_token_expires_in': 0,
            'logged_in': False
        }

        # Grab the current directory of the client file, that way we can store the JSON file in the same folder.
        dir_path = os.path.dirname(os.path.realpath(__file__))
        filename = 'ts_state.json'
        file_path = os.path.join(dir_path, filename)

        # If the state is initalized.
        if action == 'init':

            # Initalize the state.
            self.state = initialized_state

            # If they allowed for caching and the file exist, load the file.
            if self.config['cache_state'] and os.path.isfile(file_path):
                with open(file=file_path, mode='r') as state_file:
                    self.state.update(json.load(fp=state_file))

            # If they didnt allow for caching delete the file.
            elif not self.config['cache_state'] and os.path.isfile(file_path):
                os.remove(file_path)

        # if they want to save it and have allowed for caching then load the file.
        elif action == 'save' and self.config['cache_state']:
            with open(file=file_path, mode='w+') as state_file:
                json.dump(obj=self.state, fp=state_file, indent=4)

    def login(self) -> bool:
        """Logs the user into a new session.

        Overview:
        ---
        Ask the user to authenticate  themselves via the TD Ameritrade Authentication Portal. This will
        create a URL, display it for the User to go to and request that they paste the final URL into
        command window.

        Once the user is authenticated the API key is valide for 90 days, so refresh tokens may be used
        from this point, up to the 90 days.

        Returns:
        ----
        (bool): `True` if the session was logged in, `False` otherwise.
        """

        # if caching is enabled then attempt silent authentication.
        if self.config['cache_state']:

            # if it was successful, the user is authenticated.
            if self._silent_sso():

                # update the authentication state
                self.authstate = True
                return True

        # Go through the authorization process.
        self._authorize()

        # Grab the access token.
        self._grab_access_token()

        # update the authentication state
        self.authstate = True

        return True

    def logout(self) -> None:
        """Clears the current TradeStation Connection state."""

        # change state to initalized so they will have to either get a
        # new access token or refresh token next time they use the API
        self._state_manager('init')

    def _grab_access_token(self) -> bool:
        """Grabs an access token.

        Overview:
        ----
        Access token handler for AuthCode Workflow. This takes the
        authorization code parsed from the auth endpoint to call the
        token endpoint and obtain an access token.

        Returns:
        ----
        (bool): `True` if grabbing the access token was successful. `False` otherwise.
        """

        # Parse the URL
        url_dict = urllib.parse.parse_qs(self.state['redirect_code'])

        # Convert the values to a list.
        url_values = list(url_dict.values())

        # Grab the Code, which is stored in a list.
        url_code = url_values[0][0]

        # define the parameters of our access token post.
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
            'code': url_code,
            'redirect_uri': self.config['redirect_uri']
        }

        # Post the data to the token endpoint and store the response.
        token_response = requests.post(
            url=self.config['auth_endpoint'],
            data=data,
            verify=True
        )

        # Call the `_token_save` method to save the access token.
        if token_response.ok:
            self._token_save(response=token_response)
            return True
        else:
            return False

    def _silent_sso(self) -> bool:
        """Handles the silent authentication workflow.

        Overview:
        ----
        Attempt a silent authentication, by checking whether current access token
        is valid and/or attempting to refresh it. Returns True if we have successfully 
        stored a valid access token.

        Returns:
        ----
        (bool): `True` if grabbing the silent authentication was successful. `False` otherwise.
        """

        # if it's not expired we don't care.
        if self._token_validation():
            return True

        # if the current access token is expired then try and refresh access token.
        elif self.state['refresh_token'] and self._grab_refresh_token():
            return True

        # More than likely a first time login, so can't do silent authenticaiton.
        else:
            return False

    def _grab_refresh_token(self) -> bool:
        """Refreshes the current access token if it's expired.

        Returns:
        ----
        (bool): `True` if grabbing the refresh token was successful. `False` otherwise.
        """

        # Build the parameters of our request.
        data = {
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
            'grant_type': 'refresh_token',
            'response_type': 'token',
            'refresh_token': self.state['refresh_token']
        }

        # Make a post request to the token endpoint.
        response = requests.post(
            url=self.config['auth_endpoint'],
            data=data,
            verify=True
        )

        # Save the token if the response was okay.
        if response.ok:
            self._token_save(response=response)
            return True
        else:
            return False

    def _token_save(self, response: requests.Response):
        """Saves an access token or refresh token.

        Overview:
        ----
        Parses an access token from the response of a POST request and saves it
        in the state dictionary for future use. Additionally, it will store the
        expiration time and the refresh token.

        Arguments:
        ----
        response (requests.Response): A response object recieved from the `token_refresh` or `_grab_access_token`
            methods.

        Returns:
        ----
        (bool): `True` if saving the token was successful. `False` otherwise.
        """

        # Parse the data.
        json_data = response.json()

        # Save the access token.
        if 'access_token' in json_data:
            self.state['access_token'] = json_data['access_token']
        else:
            self.logout()
            return False

        # If there is a refresh token then grab it.
        if 'refresh_token' in json_data:
            self.state['refresh_token'] = json_data['refresh_token']

        # Set the login state.
        self.state['logged_in'] = True

        # Store token expiration time.
        self.state['access_token_expires_in'] = json_data['expires_in']
        self.state['access_token_expires_at'] = time.time() + \
            int(json_data['expires_in'])

        self._state_manager('save')

        return True

    def _token_seconds(self) -> int:
        """Calculates when the token will expire.

        Overview:
        ----
        Return the number of seconds until the current access token or refresh token
        will expire. The default value is access token because this is the most commonly used
        token during requests.

        Returns:
        ----
        (int): The number of seconds till expiration
        """

        # Calculate the token expire time.
        token_exp = time.time() >= self.state['access_token_expires_at']

        # if the time to expiration is less than or equal to 0, return 0.
        if not self.state['refresh_token'] or token_exp:
            token_exp = 0
        else:
            token_exp = int(token_exp)

        return token_exp

    def _token_validation(self, nseconds: int = 5) -> None:
        """Validates the Access Token.

        Overview:
        ----
        Verify the current access token is valid for at least N seconds, and
        if not then attempt to refresh it. Can be used to assure a valid token
        before making a call to the Tradestation API.

        Arguments:
        ----
        nseconds (int): The minimum number of seconds the token has to be valid for before
            attempting to get a refresh token.
        """

        if self._token_seconds() < nseconds and self.config['refresh_enabled']:
            self._grab_refresh_token()

    def _authorize(self) -> None:
        """Authorizes the session.

        Overview:
        ----
        Initalizes the oAuth Workflow by creating the URL that
        allows the user to login to the Tradestation API using their credentials
        and then will parse the URL that they paste back into the terminal.
        """

        # prepare the payload to login
        data = {
            'response_type': 'code',
            'redirect_uri': self.config['redirect_uri'],
            'client_id': self.config['client_id']
        }

        # url encode the data.
        params = urllib.parse.urlencode(data)

        # build the full URL for the authentication endpoint.
        url = 'https://api.tradestation.com/v2/authorize?' + params

        # aks the user to go to the URL provided, they will be prompted to authenticate themsevles.
        print('')
        print('='*80)
        print('')
        print('Please go to URL provided authorize your account: {}'.format(url))
        print('')
        print('-'*80)

        # ask the user to take the final URL after authentication and paste here so we can parse.
        my_response = input('Paste the full URL redirect here: ')

        # store the redirect URL
        self.state['redirect_code'] = my_response

    def _handle_requests(self, url: str, method: str, headers: dict, args: dict = None, stream: bool = False, payload: dict = None) -> dict:
        """[summary]

        Arguments:
        ----
        url (str): [description]

        method (str): [description]

        headers (dict): [description]

        args (dict, optional): [description]. Defaults to None.

        stream (bool, optional): [description]. Defaults to False.

        payload (dict, optional): [description]. Defaults to None.

        Raises:
        ----
        ValueError: [description]

        Returns:
        ----
        dict: [description]
        """

        streamed_content = []
        if method == 'get':

            # handles the non-streaming GET requests.
            if stream == False:
                response = requests.get(
                    url=url, headers=headers, params=args, verify=True)

            # handles the Streaming request.
            else:
                response = requests.get(
                    url=url, headers=headers, params=args, verify=True, stream=True)
                for line in response.iter_lines(chunk_size=300):

                    if 'END' not in line.decode() and line.decode() != '':
                        try:
                            streamed_content.append(json.loads(line))
                        except:
                            print(line)

        elif method == 'post':

            if payload is None:
                response = requests.post(
                    url=url, headers=headers, params=args, verify=True)
            else:
                response = requests.post(
                    url=url, headers=headers, params=args, verify=True, json=payload)

        elif method == 'put':

            if payload is None:
                response = requests.put(
                    url=url, headers=headers, params=args, verify=True)
            else:
                response = requests.put(
                    url=url, headers=headers, params=args, verify=True, json=payload)

        elif method == 'delete':

            response = requests.delete(
                url=url, headers=headers, params=args, verify=True)

        else:
            raise ValueError(
                'The type of request you are making is incorrect.')

        # grab the status code
        status_code = response.status_code

        # grab the response headers.
        response_headers = response.headers

        if status_code == 200:

            if response_headers['Content-Type'] == 'application/json; charset=utf-8':
                return response.json()
            elif response_headers['Transfer-Encoding'] == 'chunked':

                return streamed_content

        elif status_code == 400:

            # BAD REQUEST

            print('')
            print('-'*80)
            print("BAD REQUEST - STATUS CODE: {}".format(status_code))
            print("RESPONSE URL: {}".format(response.url))
            print("RESPONSE HEADERS: {}".format(response.headers))
            print("RESPONSE TEXT: {}".format(response.text))
            print('-'*80)
            print('')

        elif status_code == 403:

            # BAD REQUEST

            print('')
            print('-'*80)
            print("BAD REQUEST - STATUS CODE: {}".format(status_code))
            print("RESPONSE URL: {}".format(response.url))
            print("RESPONSE HEADERS: {}".format(response.headers))
            print("RESPONSE TEXT: {}".format(response.text))
            print('-'*80)
            print('')

        elif status_code == 500:

            # UNEXPECTED ERROR

            print('')
            print('-'*80)
            print("BAD REQUEST - STATUS CODE:{}".format(status_code))
            print('')
            print("RESPONSE URL:\n{}".format(response.url))
            print('')
            print("RESPONSE HEADERS:\n{}".format(response.headers))
            print('')
            print("RESPONSE TEXT:\n{}".format(response.text))
            print('-'*80)
            print('')

    def user_accounts(self, user_id: str) -> dict:
        """Grabs all the accounts associated with the User.

        Arguments:
        ----
        user_id (str): The Username of the account holder.

        Returns:
        ----
        (dict): All the user accounts.
        """

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='users/{username}/accounts'.format(username=user_id)
        )

        # define the arguments
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint,
            method='get',
            args=params
        )

        return response

    def account_balances(self, account_keys=None):

        if isinstance(account_keys, list):

            # validate the token.
            self._token_validation()

            # argument validation.
            if len(account_keys) == 0:
                raise ValueError(
                    "You cannot pass through an empty list for account keys.")
            elif len(account_keys) > 0 and len(account_keys) <= 25:
                account_keys = ','.join(account_keys)
            elif len(account_keys) > 25:
                raise ValueError(
                    "You cannot pass through more than 25 account keys.")

            # define the endpoint.
            url_endpoint = self._api_endpoint(
                url='accounts/{}/balances'.format(account_keys))

            # define the arguments
            params = {
                'access_token': self.state['access_token']
            }

            # grab the response
            response = self._handle_requests(
                url=url_endpoint, method='get', args=params)

            return response

        else:
            raise ValueError("Account Keys, must be a list object")

    def account_positions(self, account_keys=None, symbols=None):

        if isinstance(account_keys, list):

            # validate the token.
            self._token_validation()

            # argument validation, account keys.
            if len(account_keys) == 0:
                raise ValueError(
                    "You cannot pass through an empty list for account keys.")
            elif len(account_keys) > 0 and len(account_keys) <= 25:
                account_keys = ','.join(account_keys)
            elif len(account_keys) > 25:
                raise ValueError(
                    "You cannot pass through more than 25 account keys.")

            # argument validation, symbols.
            if symbols is not None:
                if len(symbols) == 0:
                    raise ValueError(
                        "You cannot pass through an empty symbols list for the filter.")
                else:

                    symbols_formatted = []
                    for symbol in symbols:
                        symbols_formatted.append(
                            "Symbol eq '{}'".format(symbol))

                    symbols = 'or '.join(symbols_formatted)
                    params = {
                        'access_token': self.state['access_token'],
                        '$filter': symbols
                    }

            else:
                params = {'access_token': self.state['access_token']}

            # define the endpoint.
            url_endpoint = self._api_endpoint(
                url='accounts/{}/positions'.format(account_keys))

            # grab the response
            response = self._handle_requests(
                url=url_endpoint, method='get', args=params)

            return response
        else:
            raise ValueError("Account Keys, must be a list object")

    def account_orders(self, account_keys=None, since=None, page_size=None, page_number=None):

        if isinstance(account_keys, list):

            # validate the token.
            self._token_validation()

            # argument validation, account keys.
            if len(account_keys) == 0:
                raise ValueError(
                    "You cannot pass through an empty list for account keys.")
            elif len(account_keys) > 0 and len(account_keys) <= 25:
                account_keys = ','.join(account_keys)
            elif len(account_keys) > 25:
                raise ValueError(
                    "You cannot pass through more than 25 account keys.")

            # argument validation, SINCE
            if since:
                if since > 14:
                    raise ValueError(
                        "You can't get orders older than 14 days old.")
                elif since <= 0:
                    raise ValueError(
                        "You can't specify since as a 0 or a negative number.")

                today = date.today()
                today = date(year=today.year, month=today.month, day=since)
                date_format = today.strftime("%m/%d/%Y")

            else:
                date_format = None

            params = {
                'access_token': self.state['access_token'],
                'since': date_format,
                'pageSize': page_size,
                'pageNum': page_number
            }

            # define the endpoint.
            url_endpoint = self._api_endpoint(
                url='accounts/{}/orders'.format(account_keys))

            # grab the response
            response = self._handle_requests(
                url=url_endpoint, method='get', args=params)

            return response

        else:
            raise ValueError("Account Keys, must be a list object")

    def symbol_info(self, symbol=None):

        # validate the token.
        self._token_validation()

        if symbol is None:
            raise ValueError("You must pass through a symbol.")

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='data/symbol/{}'.format(symbol))

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params)

        return response

    def quotes(self, symbols=None):

        # validate the token.
        self._token_validation()

        if symbols is None:
            raise ValueError("You must pass through at least one symbol.")

        symbols = ','.join(symbols)

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='data/quote/{}'.format(symbols))

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params)

        return response

    def stream_quotes_changes(self, symbols=None):

        # validate the token.
        self._token_validation()

        if symbols is None:
            raise ValueError("You must pass through at least one symbol.")

        symbols = ','.join(symbols)

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='stream/quote/changes/{}'.format(symbols))

        # define the headers
        headers = {
            'Accept': 'application/vnd.tradestation.streams+json'
        }

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', headers=headers, args=params, stream=True)

        return response

    def stream_bars_start_date(self, symbol=None, interval=None, unit=None, start_date=None, session=None):

        # ['USEQPre','USEQPost','USEQPreAndPost','Default']

        # validate the token.
        self._token_validation()

        if symbol is None:
            raise ValueError("You must pass through one symbol.")

        if unit not in ["Minute", "Daily", "Weekly", "Monthly"]:
            raise ValueError(
                'The value you passed through for `unit` is incorrect, it must be one of the following: ["Minute", "Daily", "Weekly", "Monthly"]')

        if interval != 1 and unit in ["Daily", "Weekly", "Monthly"]:
            raise ValueError(
                "The interval must be one for daily, weekly or monthly.")
        elif interval > 1440:
            raise ValueError("Interval must be less than or equal to 1440")

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='stream/barchart/{}/{}/{}/{}'.format(symbol, interval, unit, start_date))

        # define the arguments.
        params = {
            'access_token': self.state['access_token'],
            'sessionTemplate': session
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params, stream=True)

        return response

    def stream_bars_date_range(self, symbol=None, interval=None, unit=None, start_date=None, end_date=None, session=None):

        # validate the token.
        self._token_validation()

        # validate the symbol
        if symbol is None:
            raise ValueError("You must pass through one symbol.")

        # validate the unit
        if unit not in ["Minute", "Daily", "Weekly", "Monthly"]:
            raise ValueError(
                'The value you passed through for `unit` is incorrect, it must be one of the following: ["Minute", "Daily", "Weekly", "Monthly"]')

        # validate the interval.
        if interval != 1 and unit in ["Daily", "Weekly", "Monthly"]:
            raise ValueError(
                "The interval must be one for daily, weekly or monthly.")
        elif interval > 1440:
            raise ValueError("Interval must be less than or equal to 1440")

        # validate the session.
        if session is not None and session not in ['USEQPre', 'USEQPost', 'USEQPreAndPost', 'Default']:
            raise ValueError(
                'The value you passed through for `session` is incorrect, it must be one of the following: ["USEQPre","USEQPost","USEQPreAndPost","Default"]')

        # validate the START DATE.
        if isinstance(start_date, datetime.datetime) or isinstance(start_date, datetime.date):
            start_date_iso = start_date.isoformat()
        elif isinstance(start_date, str):
            datetime_parsed = parse(start_date)
            start_date_iso = datetime_parsed.isoformat()

        # validate the END DATE.
        if isinstance(end_date, datetime.datetime) or isinstance(start_date, datetime.date):
            end_date_iso = end_date.isoformat()

        elif isinstance(end_date, str):
            datetime_parsed = parse(end_date)
            end_date_iso = datetime_parsed.isoformat()

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='stream/barchart/{}/{}/{}/{}/{}'.format(
            symbol, interval, unit, start_date_iso, end_date_iso))

        # define the arguments.
        params = {
            'access_token': self.state['access_token'],
            'sessionTemplate': session
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params, stream=True)

        return response

    def stream_bars_back(self, symbol=None, interval=None, unit=None, bar_back=None, last_date=None, session=None):

        # validate the token.
        self._token_validation()

        # validate the symbol
        if symbol is None:
            raise ValueError("You must pass through one symbol.")

        # validate the unit
        if unit not in ["Minute", "Daily", "Weekly", "Monthly"]:
            raise ValueError(
                'The value you passed through for `unit` is incorrect, it must be one of the following: ["Minute", "Daily", "Weekly", "Monthly"]')

        # validate the interval.
        if interval != 1 and unit in ["Daily", "Weekly", "Monthly"]:
            raise ValueError(
                "The interval must be one for daily, weekly or monthly.")
        elif interval > 1440:
            raise ValueError("Interval must be less than or equal to 1440")

        # validate the session.
        if session is not None and session not in ['USEQPre', 'USEQPost', 'USEQPreAndPost', 'Default']:
            raise ValueError(
                'The value you passed through for `session` is incorrect, it must be one of the following: ["USEQPre","USEQPost","USEQPreAndPost","Default"]')

        if bar_back > 157600:
            raise ValueError("`bar_back` must be less than or equal to 157600")

        if isinstance(last_date, datetime.datetime):
            last_date_iso = last_date.isoformat()

        elif isinstance(last_date, str):
            datetime_parsed = parse(last_date)
            last_date_iso = datetime_parsed.isoformat()

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='stream/barchart/{}/{}/{}/{}/{}'.format(symbol, interval, unit, bar_back, last_date_iso))

        # define the arguments.
        params = {
            'access_token': self.state['access_token'],
            'sessionTemplate': session
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params, stream=True)

        return response

    def stream_bars_days_back(self, symbol=None, interval=None, unit=None, bar_back=None, last_date=None, session=None):

        # validate the token.
        self._token_validation()

        # validate the symbol
        if symbol is None:
            raise ValueError("You must pass through one symbol.")

        # validate the unit
        if unit not in ["Minute", "Daily", "Weekly", "Monthly"]:
            raise ValueError(
                'The value you passed through for `unit` is incorrect, it must be one of the following: ["Minute", "Daily", "Weekly", "Monthly"]')

        # validate the interval.
        if interval != 1 and unit in ["Daily", "Weekly", "Monthly"]:
            raise ValueError(
                "The interval must be one for daily, weekly or monthly.")
        elif interval > 1440:
            raise ValueError("Interval must be less than or equal to 1440")

        # validate the session.
        if session is not None and session not in ['USEQPre', 'USEQPost', 'USEQPreAndPost', 'Default']:
            raise ValueError(
                'The value you passed through for `session` is incorrect, it must be one of the following: ["USEQPre","USEQPost","USEQPreAndPost","Default"]')

        if bar_back > 157600:
            raise ValueError("`bar_back` must be less than or equal to 157600")

        if isinstance(last_date, datetime.datetime):
            last_date_iso = last_date.isoformat()

        elif isinstance(last_date, str):
            datetime_parsed = parse(last_date)
            last_date_iso = datetime_parsed.isoformat()

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='stream/barchart/{}/{}/{}/{}/{}'.format(symbol, interval, unit, bar_back, last_date_iso))

        # define the arguments.
        params = {
            'access_token': self.state['access_token'],
            'sessionTemplate': session
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params, stream=True)

        return response

    def stream_bars(self, symbol=None, interval=None, bar_back=None):

        # validate the token.
        self._token_validation()

        # validate the symbol
        if symbol is None:
            raise ValueError("You must pass through one symbol.")

        if interval > 64999:
            raise ValueError("Interval must be less than or equal to 64999")

        if bar_back > 10:
            raise ValueError("`bar_back` must be less than or equal to 10")

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='stream/tickbars/{}/{}/{}'.format(symbol, interval, bar_back))

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params, stream=True)

        return response

    def symbol_lists(self):

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='data/symbollists')

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params)

        return response

    def symbol_list(self, symbol_list_id=None):

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='data/symbollists/{}'.format(symbol_list_id))

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params)

        return response

    def symbols_from_symbol_list(self, symbol_list_id=None):

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='data/symbollists/{}/symbols'.format(symbol_list_id))

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='get', args=params)

        return response

    def confirm_order(self, order=None):

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='orders/confirm')

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='post', args=params, payload=order)

        return response

    def submit_order(self, order=None):

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='orders')

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='post', args=params, payload=order)

        return response

    def cancel_order(self, order_id=None):

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='orders/{}'.format(order_id))

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='delete', args=params)

        return response

    def replace_order(self, order_id: str, new_order: dict) -> dict:

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='orders/{order_id}'.format(order_id=order_id)
        )

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint,
            method='put',
            args=params,
            payload=new_order
        )

        return response

    def confirm_group_order(self, orders: List[Dict]) -> dict:

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='orders/groups/confirm')

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint, method='post', args=params, payload=orders)

        return response

    def submit_group_order(self, orders: List[Dict]) -> dict:

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='orders/groups')

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint,
            method='post',
            args=params,
            payload=orders
        )

        return response

    def available_activation_triggers(self):
        """Grabs all the Activiation Triggers.

        Returns:
        (dict): A dictionary resource with all the activation triggers.
        """

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(
            url='orderexecution/activationtriggers'
        )

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint,
            method='get',
            args=params
        )

        return response

    def available_exchanges(self) -> dict:
        """Grabs all the exchanges provided by TradeStation.

        Returns:
        (dict): A dictionary resource with all the exchanges listed.
        """

        # validate the token.
        self._token_validation()

        # define the endpoint.
        url_endpoint = self._api_endpoint(url='orderexecution/exchanges')

        # define the arguments.
        params = {
            'access_token': self.state['access_token']
        }

        # grab the response
        response = self._handle_requests(
            url=url_endpoint,
            method='get',
            args=params
        )

        return response
