/**
*
* Copyright (c) Microsoft Corporation.
* All rights reserved.
*
* This code is licensed under the MIT License.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files(the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions :
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*
*/


#include "auth_delegate_impl.h"
#include "auth.h"

#include <stdexcept>

using std::runtime_error;
using std::string;

namespace sample {
	namespace auth {

		AuthDelegateImpl::AuthDelegateImpl(
			const mip::ApplicationInfo& applicationInfo)
			: mApplicationInfo(applicationInfo) {
			}

		AuthDelegateImpl::AuthDelegateImpl(
			const mip::ApplicationInfo& applicationInfo,
			const std::string& username,
			const std::string& password)
			: mApplicationInfo(applicationInfo),
			  mUserName(username),
			  mPassword(password) {
		}
			
		bool AuthDelegateImpl::AcquireOAuth2Token(
			const mip::Identity& /*identity*/,
			const OAuth2Challenge& challenge,
			OAuth2Token& token) {
			
			// call our AcquireToken function, passing in username, password, clientId, and getting the resource/authority from the OAuth2Challenge object
			string accessToken = sample::auth::AcquireToken(mUserName, mPassword, mApplicationInfo.applicationId, challenge.GetResource(), challenge.GetAuthority());
			//string accessToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1zeE1KTUxDSURXTVRQdlp5SjZ0eC1DRHh3MCIsImtpZCI6Ii1zeE1KTUxDSURXTVRQdlp5SjZ0eC1DRHh3MCJ9.eyJhdWQiOiJodHRwczovL2FhZHJtLmNvbSIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2NiNDZjMDMwLTE4MjUtNGU4MS1hMjk1LTE1MWMwMzlkYmYwMi8iLCJpYXQiOjE1NTA3OTM2MTUsIm5iZiI6MTU1MDc5MzYxNSwiZXhwIjoxNTUwNzk3NTE1LCJhY3IiOiIxIiwiYWlvIjoiNDJKZ1lOamI1WEs3cGtpMytrWDRiQU1lbmgwN00wci9UTjk5U1M5OTI2ZDJ5L1NKc3EwQSIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiI2YjA2OWVlZi05ZGRlLTRhMjktYjQwMi04Y2U4NjZlZGM4OTciLCJhcHBpZGFjciI6IjAiLCJkZXZpY2VpZCI6Ijg3NjRhMjk0LTI3ZWQtNDZkNy1iZTdkLTI2NWIzZWY1MzhhZSIsImdpdmVuX25hbWUiOiJVc2VyMSIsImlwYWRkciI6IjEzMS4xMDcuMTc0LjEzMSIsIm5hbWUiOiJVc2VyMSIsIm9pZCI6IjNhNDY4NDg3LTc2YTctNDRmNy05NTM3LTMxMzQ0NTE1ZjU2NiIsInB1aWQiOiIxMDAzM0ZGRkFGNUQ2OTE0Iiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwic3ViIjoiUnRmRnFpRXpGcXR5SDBwXzlPTmU5ajlVdl9pZXAzRmJxR2hoLWY0bnVzYyIsInRpZCI6ImNiNDZjMDMwLTE4MjUtNGU4MS1hMjk1LTE1MWMwMzlkYmYwMiIsInVuaXF1ZV9uYW1lIjoiVXNlcjFAbWlsdDByLmNvbSIsInVwbiI6IlVzZXIxQG1pbHQwci5jb20iLCJ1dGkiOiJ5Wl9sM1RTejIwV2Rva1p5VW5zQUFBIiwidmVyIjoiMS4wIn0.KYkEryLXbwDkIsNyiOd21-bq6y4WaeLPhAKWL5rti_c2bGBZOQaG_DqZ3_hGg564fWzFCwdPqRW4pPVMzPyNnnUxnGPE4sro4uJwBZOc40XTFcm9gnu0h5HNAdFFvuVZBoQM6wKQoH5AykRSXarsWWPCpu0lxgvH8XOGX3JXIDeN2dGdjcxAfCpkD65wvm830em3RWITxAgDyKs8yiTfxYDtnqfBmGygH17LHPoxefOUCqooWPqU42GuBRtWH6fknqjfvkjrNMulNUFXGppw8-ye-piZYMwe45uLEvWQ0Qr-Wm0Eci89CFjqXksTcheMMa4e2W7eKYv2vVyB486tkw";
			token.SetAccessToken(accessToken);
			return true;
		}

	} // namespace sample
} // namespace auth
