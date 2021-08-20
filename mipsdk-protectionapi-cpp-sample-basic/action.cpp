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

#include "action.h"

#include "mip/common_types.h"
#include "mip/protection/protection_profile.h"
#include "mip/protection/protection_engine.h"
#include "mip/protection/protection_handler.h"
#include "mip/protection_descriptor.h"
#include "mip/protection/protection_descriptor_builder.h"
#include "mip/protection/roles.h"
#include "mip/protection/rights.h"


#include "auth_delegate_impl.h"
#include "consent_delegate_impl.h"
#include "protection_observers.h"
#include "utils.h"

#include <iostream>
#include <stdexcept>
#include <stdio.h>

#ifdef _WIN32
	#define FREAD(buffer, elementSize, count, stream) fread_s(buffer, count, elementSize, count, stream)
#else
	#define FREAD fread
#endif

using std::cout;
using std::endl;

using mip::ProtectionProfile;
using mip::ProtectionEngine;
using mip::ProtectionHandler;

namespace sample {
	namespace protection {

		// Constructor accepts mip::ApplicationInfo object and uses it to initialize AuthDelegateImpl.
		// Specifically, AuthDelegateInfo uses mAppInfo.ApplicationId for AAD client_id value.		
		Action::Action(const mip::ApplicationInfo appInfo,
			const std::string& username,
			const std::string& password)
			: mAppInfo(appInfo),
			mUsername(username),
			mPassword(password) {
			mAuthDelegate = std::make_shared<sample::auth::AuthDelegateImpl>(mAppInfo, mUsername, mPassword);
		}
		
		Action::~Action()
		{
			mEngine = nullptr;
			mProfile = nullptr;
			mMipContext->ShutDown();
			mMipContext = nullptr;
		}

		void sample::protection::Action::AddNewProtectionProfile()
		{							
			// Initialize MipConfiguration
			std::shared_ptr<mip::MipConfiguration> mipConfiguration = std::make_shared<mip::MipConfiguration>(mAppInfo,
				"mip_data",
				mip::LogLevel::Trace,
				false);

			// Initialize MipContext. MipContext can be set to null at shutdown and will automatically release all resources.
			mMipContext = mip::MipContext::Create(mipConfiguration);


			// Initialize ProtectionProfileSettings using MipContext
			ProtectionProfile::Settings profileSettings(mMipContext,
				mip::CacheStorageType::OnDiskEncrypted,
				std::make_shared<sample::consent::ConsentDelegateImpl>(),
				std::make_shared<ProtectionProfileObserverImpl>()
			);

			auto profilePromise = std::make_shared<std::promise<std::shared_ptr<ProtectionProfile>>>();
			auto profileFuture = profilePromise->get_future();			
			ProtectionProfile::LoadAsync(profileSettings, profilePromise);			
			mProfile = profileFuture.get();
		}
		
		void Action::AddNewProtectionEngine()
		{			
			if (!mProfile)
			{
				AddNewProtectionProfile();
			}
		
			// Set the engine identity to the provided username. This username is used for service discovery.
			ProtectionEngine::Settings engineSettings(mip::Identity(mUsername), mAuthDelegate, "");
			
			// Set the engine Id to the username of the authenticated user. This will ensure that the same engine is loaded and the cache utilized properly. 
			engineSettings.SetEngineId(mUsername);

			auto enginePromise = std::make_shared<std::promise<std::shared_ptr<ProtectionEngine>>>();
			auto engineFuture = enginePromise->get_future();
			mProfile->AddEngineAsync(engineSettings, enginePromise);
			mEngine = engineFuture.get();	

			// Output the engine id to the console. 
			cout << "Engine Id: " << mEngine->GetSettings().GetEngineId() << endl;
		}
		
		std::shared_ptr<mip::ProtectionHandler> Action::CreateProtectionHandlerForPublishing(const std::shared_ptr<mip::ProtectionDescriptor>& descriptor)
		{
			auto handlerPromise = std::make_shared<std::promise<std::shared_ptr<ProtectionHandler>>>();
			auto handlerFuture = handlerPromise->get_future();

			auto handlerObserver = std::make_shared<ProtectionHandlerObserverImpl>();

			mip::ProtectionHandler::PublishingSettings publishingSettings = mip::ProtectionHandler::PublishingSettings(descriptor);
			mEngine->CreateProtectionHandlerForPublishingAsync(publishingSettings, handlerObserver, handlerPromise);
			
			auto handler = handlerFuture.get();			
			
			return handler;
		}

		std::shared_ptr<mip::ProtectionHandler> Action::CreateProtectionHandlerForConsumption(const std::vector<uint8_t>& serializedPublishingLicense) {
			// Note: Applications can optionally require user consent to acquire a protection handler by implementing the
			//  ConsentDelegate interfaces and passing the object when creating a ProtectionProfile

			auto handlerPromise = std::make_shared<std::promise<std::shared_ptr<ProtectionHandler>>>();
			auto handlerFuture = handlerPromise->get_future();
			shared_ptr<ProtectionHandlerObserverImpl> handlerObserver = std::make_shared<ProtectionHandlerObserverImpl>();

			mip::ProtectionHandler::ConsumptionSettings consumptionSettings = mip::ProtectionHandler::ConsumptionSettings(serializedPublishingLicense);
			mEngine->CreateProtectionHandlerForConsumptionAsync(consumptionSettings, handlerObserver, handlerPromise);
			
			auto h = handlerFuture.get();						
			return h;
		}
	

		std::shared_ptr<mip::ProtectionDescriptor> Action::CreateProtectionDescriptor(const ProtectionOptions protectionOptions)
		{
			if (!protectionOptions.templateId.empty())
			{
				auto descriptorBuilder = mip::ProtectionDescriptorBuilder::CreateFromTemplate(protectionOptions.templateId);				
				return descriptorBuilder->Build();
			}
			return nullptr;
		}


		// Function recursively lists all labels available for a user to	std::cout.
		void Action::ListTemplates() {

			// If mEngine hasn't been set, call AddNewFileEngine() to load the engine.
			if (!mEngine) {			
				AddNewProtectionEngine();
			}

			const shared_ptr<ProtectionEngineObserverImpl> engineObserver = std::make_shared<ProtectionEngineObserverImpl>();

			// Create a context to pass to 'ProtectionEngine::GetTemplateListAsync'. That context will be forwarded to the
			// corresponding ProtectionEngine::Observer methods. In this case, we use promises/futures as a simple way to detect 
			// the async operation completes synchronously.
			auto loadPromise = std::make_shared<std::promise<vector<shared_ptr<mip::TemplateDescriptor>>>>();
			std::future<vector<shared_ptr<mip::TemplateDescriptor>>> loadFuture = loadPromise->get_future();
			mEngine->GetTemplatesAsync(engineObserver, loadPromise);
			auto templates = loadFuture.get();
			
			for (const auto& protectionTemplate: templates) {
				cout << "Name: " << protectionTemplate->GetName() << " : " << protectionTemplate->GetId() << endl;				
			}
		}

		std::vector<uint8_t> Action::ProtectString(const std::string& plaintext, std::string& ciphertext, const std::string& templateId)
		{
			if (!mEngine) {
				AddNewProtectionEngine();
			}

			ProtectionOptions protectionOptions;
			protectionOptions.templateId = templateId;

			auto descriptor = CreateProtectionDescriptor(protectionOptions);

			auto handler = CreateProtectionHandlerForPublishing(descriptor);
			std::vector<uint8_t> outputBuffer;
			// std::vector<uint8_t> inputBuffer(static_cast<size_t>(plaintext.size()));
			std::vector<uint8_t> inputBuffer(plaintext.begin(), plaintext.end());

			outputBuffer.resize(static_cast<size_t>(handler->GetProtectedContentLength(plaintext.size(), true)));
			
			handler->EncryptBuffer(0,
				&inputBuffer[0],
				static_cast<int64_t>(inputBuffer.size()),
				&outputBuffer[0],
				static_cast<int64_t>(outputBuffer.size()),
				true);
			
			std::string output(outputBuffer.begin(), outputBuffer.end());
			ciphertext = output;

			return handler->GetSerializedPublishingLicense();
		}

		void Action::DecryptString(std::string& plaintext, const std::string& ciphertext, const std::vector<uint8_t>& serializedLicense)
		{
			if (!mEngine) {
				AddNewProtectionEngine();
			}

			auto handler = CreateProtectionHandlerForConsumption(serializedLicense);
			std::vector<uint8_t> outputBuffer(static_cast<size_t>(ciphertext.size()));

				
			// std::vector<uint8_t> inputBuffer(static_cast<size_t>(plaintext.size()));
			std::vector<uint8_t> inputBuffer(ciphertext.begin(), ciphertext.end());
			
			int64_t decryptedSize = handler->DecryptBuffer(
				0,
				&inputBuffer[0],
				static_cast<int64_t>(inputBuffer.size()),
				&outputBuffer[0],
				static_cast<int64_t>(outputBuffer.size()),
				true);
			outputBuffer.resize(static_cast<size_t>(decryptedSize));
						
			std::string output(outputBuffer.begin(), outputBuffer.end());
			plaintext = output;
		}
	}
}
