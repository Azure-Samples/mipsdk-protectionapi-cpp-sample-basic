#include "protection_observers.h"

#include <iostream>
#include <stdexcept>
#include <stdio.h>

#include "mip/protection/protection_profile.h"
#include "mip/protection/protection_engine.h"
#include "mip/protection/protection_handler.h"

using std::shared_ptr;
using std::future;
using std::promise;
using std::vector;
using std::string;
using std::exception_ptr;

// Protection Profile Observers
void ProtectionProfileObserverImpl::OnLoadSuccess(
	const shared_ptr<mip::ProtectionProfile>& profile,
	const shared_ptr<void>& context) {
	auto loadPromise = static_cast<promise<shared_ptr<mip::ProtectionProfile>>*>(context.get());
	loadPromise->set_value(profile);
};

void ProtectionProfileObserverImpl::OnLoadFailure(const exception_ptr& Failure, const shared_ptr<void>& context) {
	auto loadPromise = static_cast<promise<shared_ptr<mip::ProtectionProfile>>*>(context.get());
	loadPromise->set_exception(Failure);
};

void ProtectionProfileObserverImpl::OnAddEngineSuccess(
	const shared_ptr<mip::ProtectionEngine>& engine,
	const shared_ptr<void>& context) {
	auto addEnginePromise = static_cast<promise<shared_ptr<mip::ProtectionEngine>>*>(context.get());
	addEnginePromise->set_value(engine);
};

void ProtectionProfileObserverImpl::OnAddEngineFailure(
	const exception_ptr& Failure,
	const shared_ptr<void>& context) {
	auto addEnginePromise = static_cast<promise<shared_ptr<mip::ProtectionEngine>>*>(context.get());
	addEnginePromise->set_exception(Failure);
};

void ProtectionHandlerObserverImpl::OnCreateProtectionHandlerSuccess(
	const shared_ptr<mip::ProtectionHandler>& protectionHandler,
	const shared_ptr<void>& context) {
	auto createProtectionHandlerPromise = static_cast<promise<shared_ptr<mip::ProtectionHandler>>*>(context.get());
	createProtectionHandlerPromise->set_value(protectionHandler);
};

void ProtectionHandlerObserverImpl::OnCreateProtectionHandlerFailure(
	const exception_ptr& Failure,
	const shared_ptr<void>& context) {
	auto createProtectionHandlerPromise = static_cast<promise<shared_ptr<mip::ProtectionHandler>>*>(context.get());
	createProtectionHandlerPromise->set_exception(Failure);
};

void ProtectionEngineObserverImpl::OnGetTemplatesSuccess(
	const vector<shared_ptr<mip::TemplateDescriptor>>& templateDescriptors,
	const shared_ptr<void>& context) {
	auto loadPromise = static_cast<promise<vector<shared_ptr<mip::TemplateDescriptor>>>*>(context.get());	
	loadPromise->set_value(templateDescriptors);
};

void ProtectionEngineObserverImpl::OnGetTemplatesFailure(const exception_ptr& Failure, const shared_ptr<void>& context) {
	auto loadPromise = static_cast<promise<shared_ptr<mip::ProtectionProfile>>*>(context.get());
	loadPromise->set_exception(Failure);
};


