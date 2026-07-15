#
# Copyright (c) Microsoft Corporation.
# All rights reserved.
#
# This code is licensed under the MIT License.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions :
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import getopt
import sys

from msal import PublicClientApplication


def print_usage():
    print("auth.py -u <username> -a <authority> -r <resource> -c <clientId>")


def normalize_authority(authority):
    # ONLY FOR DEMO PURPOSES AND MSAL FOR PYTHON
    # This shouldn't be required when using proper auth flows in production.
    if authority.find("common") > 1:
        authority = authority.split("/common")[0] + "/organizations"
    return authority


def normalize_scope(resource):
    if resource.endswith("/"):
        return resource + ".default"
    return resource + "/.default"


def acquire_access_token(app, username, scope):
    accounts = app.get_accounts(username=username)
    for account in accounts:
        silent_result = app.acquire_token_silent(scopes=[scope], account=account)
        if silent_result and "access_token" in silent_result:
            return silent_result["access_token"], None

    interactive_result = app.acquire_token_interactive(scopes=[scope], login_hint=username)
    if interactive_result and "access_token" in interactive_result:
        return interactive_result["access_token"], None

    if interactive_result:
        if "error_description" in interactive_result:
            return None, interactive_result["error_description"]
        if "error" in interactive_result:
            return None, interactive_result["error"]

    return None, "Unknown authentication failure."


def main(argv):
    try:
        options, _ = getopt.getopt(argv, "hu:a:r:c:")
    except getopt.GetoptError:
        print_usage()
        sys.exit(-1)

    username = ""
    authority = ""
    resource = ""
    client_id = ""

    for option, arg in options:
        if option == "-h":
            print_usage()
            sys.exit()
        if option == "-u":
            username = arg
        elif option == "-a":
            authority = arg
        elif option == "-r":
            resource = arg
        elif option == "-c":
            client_id = arg

    if username == "" or authority == "" or resource == "" or client_id == "":
        print_usage()
        sys.exit(-1)

    authority = normalize_authority(authority)
    scope = normalize_scope(resource)
    app = PublicClientApplication(client_id=client_id, authority=authority)

    access_token, error = acquire_access_token(app, username, scope)
    if access_token:
        print(access_token)
        return

    print(error, file=sys.stderr)
    sys.exit(-1)


if __name__ == "__main__":
    main(sys.argv[1:])
