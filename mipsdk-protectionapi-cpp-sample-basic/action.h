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


#ifndef SAMPLES_ACTION_H_
#define SAMPLES_ACTION_H_

#include <memory>
#include <string>

#include "mip/mip_context.h"
#include "mip/common_types.h"
#include "mip/protection/protection_profile.h"
#include "mip/protection/protection_engine.h"
#include "mip/protection/protection_handler.h"
#include "mip/protection_descriptor.h"
#include "mip/protection/rights.h"

#include "protection_observers.h"
#include "auth_delegate_impl.h"
#include "consent_delegate_impl.h"

namespace sample {
	namespace protection {	

		struct ProtectionOptions {
			bool isAdHoc = false;
			std::vector<std::string> owner;
			std::vector<std::string> users;
			std::vector<std::string> rights;
			std::vector<std::string> roles;
			std::string templateId;
			bool useBufferApi = false;
		};

		class Action {
		public:

			Action(const mip::ApplicationInfo appInfo,
				const std::string& username);
			~Action();

			void ListTemplates();							// List all labels associated engine loaded for user						
			std::vector<uint8_t> ProtectString(const std::string& plaintext, std::string& ciphertext, const std::string& templateId);
			void DecryptString(std::string& plaintext, const std::string& ciphertext, const std::vector<uint8_t>& serializedLicense);
			void ShowProtection(const std::vector<uint8_t>& serializedLicense);

		private:
			void AddNewProtectionProfile();					// Private function for adding and loading mip::FileProfile
			void AddNewProtectionEngine();					// Private function for adding/loading mip::FileEngine for specified user
			std::shared_ptr<mip::ProtectionHandler> CreateProtectionHandlerForPublishing(const std::shared_ptr<mip::ProtectionDescriptor>& descriptor); // Creates mip::FileHandler for specified file
			shared_ptr<mip::ProtectionHandler> CreateProtectionHandlerForConsumption(const vector<uint8_t>& serializedPublishingLicense);
			std::shared_ptr<mip::ProtectionDescriptor> CreateProtectionDescriptor(const ProtectionOptions protectionOptions);

			std::shared_ptr<sample::auth::AuthDelegateImpl> mAuthDelegate;			// AuthDelegateImpl object that will be used throughout the sample to store auth details.
			std::shared_ptr<mip::MipContext> mMipContext;
			std::shared_ptr<mip::ProtectionProfile> mProfile;								// mip::FileProfile object to store/load state information 
			std::shared_ptr<mip::ProtectionEngine> mEngine;								// mip::FileEngine object to handle user-specific actions. 
			std::shared_ptr<sample::consent::ConsentDelegateImpl> mConsentDelegate; // Implements consent flow. Review consent_delegate_impl.cpp for implementation details.						
			mip::ApplicationInfo mAppInfo;											// mip::ApplicationInfo object for storing client_id and friendlyname

			std::string mUsername; // store username to pass to auth delegate and to generate Identity
		};

		

	}
}


#endif
