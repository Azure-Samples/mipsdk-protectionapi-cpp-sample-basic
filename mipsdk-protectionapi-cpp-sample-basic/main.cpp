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

#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>


#include "action.h"
#include "auth.h"
#include "mip/common_types.h"
#include "utils.h"

using std::make_shared;
using std::shared_ptr;
using std::string;

using std::cout;
using std::cin;
using std::endl;

using sample::protection::Action;

int RunSample(int argc, char* argv[])
{
	if (argc == 2 && std::string(argv[1]) == "--auth-host-smoke")
	{
		try
		{
			return sample::auth::ValidateManagedHost() ? 0 : 1;
		}
		catch (const std::exception&)
		{
			return 1;
		}
	}

	// Local variables for template selection and plaintext/ciphertext flow.
	
	string templateToApply;
	string plaintext;
	string ciphertext;
	string decryptedText;
	
	// Client ID should be the client ID registered in Microsoft Entra ID for your custom application.
	std::string clientId = "YOUR CLIENT ID";

	// Username is used as identity and a login hint for browser-based sign-in.
	std::string userName = "YOUR TEST USER ID";

	// Create the mip::ApplicationInfo object. 

	// Friendly Name should be the name of the application as it should appear in reports.
	mip::ApplicationInfo appInfo{ clientId,  "MIP SDK Protection Sample for C++", "1.18.0" };

	// Sample operations are implemented in sample::protection::Action (Action.h/cpp).
	// Action's constructor accepts app metadata and the username used for authentication.
	Action action = Action(appInfo, userName);

	while (true)
	{
		templateToApply = "";

		// Display all available protection templates.
		cout << "*** Template List: " << endl;
		action.ListTemplates();		

		// Prompt for a template ID from the list.
		cout << "Copy a template ID from above to apply to a new string or q to quit." << endl;
		cout << endl << "Template ID: ";
		cin >> templateToApply;

		if (templateToApply == "q")
		{
			return 0;
		}

		// Prompt for plaintext to encrypt.
		cout << "Enter some text to encrypt: ";
		std::getline(std::cin >> std::ws, plaintext);
				
		// Show selected template and input text.
		cout << "Applying template ID " + templateToApply + " to: " << endl << plaintext << endl;

		// Protect the input string using the previously generated PL.
		auto publishingLicense = action.ProtectString(plaintext, ciphertext, templateToApply);

		cout << "Protected output: " << endl << ciphertext << endl;
		cout << endl << "Decrypting string: " << endl << endl;

		// Use the same PL to decrypt the ciphertext.
		action.DecryptString(decryptedText, ciphertext, publishingLicense);

		// Output decrypted content. Should match original input text.
		cout << decryptedText << endl;

		system("pause");
	}
		
	return 0;
}

int main(int argc, char* argv[])
{
	try
	{
		return RunSample(argc, argv);
	}
	catch (const std::exception& error)
	{
		std::cerr << "Sample failed: " << error.what() << std::endl;
		return 1;
	}
	catch (...)
	{
		std::cerr << "Sample failed." << std::endl;
		return 1;
	}
}
