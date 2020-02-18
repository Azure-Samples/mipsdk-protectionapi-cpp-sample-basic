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


#ifndef SAMPLES_PROTECTION_OBSERVERS_H_
#define SAMPLES_PROTECTION_OBSERVERS_H_

#include "mip/protection/protection_profile.h"
#include "mip/protection/protection_handler.h"


using std::shared_ptr;
using std::vector;
using std::string;
using std::exception_ptr;


class ProtectionProfileObserverImpl final : public mip::ProtectionProfile::Observer {
public:
	ProtectionProfileObserverImpl() { }
	void OnLoadSuccess(const shared_ptr<mip::ProtectionProfile>& profile, const shared_ptr<void>& context) override;
	void OnLoadFailure(const exception_ptr& Failure, const shared_ptr<void>& context) override;
	void OnAddEngineSuccess(const shared_ptr<mip::ProtectionEngine>& engine, const shared_ptr<void>& context) override;
	void OnAddEngineFailure(const exception_ptr& Failure, const shared_ptr<void>& context) override;
};

class ProtectionHandlerObserverImpl final : public mip::ProtectionHandler::Observer {
public:
	ProtectionHandlerObserverImpl() { }
	void OnCreateProtectionHandlerSuccess(const shared_ptr<mip::ProtectionHandler>& protectionHandler, const shared_ptr<void>& context) override;
	void OnCreateProtectionHandlerFailure(const exception_ptr& Failure, const shared_ptr<void>& context) override;
};


class ProtectionEngineObserverImpl final : public mip::ProtectionEngine::Observer {
public:
	ProtectionEngineObserverImpl() { }
	void OnGetTemplatesSuccess(const vector<std::shared_ptr<mip::TemplateDescriptor>>& templateDescriptors, const shared_ptr<void>& context) override;
	void OnGetTemplatesFailure(const exception_ptr& Failure, const shared_ptr<void>& context) override;
};

#endif