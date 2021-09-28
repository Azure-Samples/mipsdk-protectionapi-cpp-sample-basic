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
#include <fstream>

#include "action.h"
#include "mip/common_types.h"
#include "utils.h"

using std::make_shared;
using std::shared_ptr;
using std::string;

using std::cout;
using std::cin;
using std::endl;

using sample::protection::Action;

void write_vector_to_disk(std::string file_path, std::vector<uint8_t>& publishingLicense);
std::vector<uint8_t> read_vector_from_disk(std::string file_path);
void decryptString(sample::protection::Action& action);
int encryptString(sample::protection::Action& action);
void printVector(std::vector<uint8_t>& vector);

int main()
{
	// Client ID should be the client ID registered in Azure AD for your custom application.
	std::string clientId = "";

	// Username and password are required in this sample as the oauth2 token is obtained via Python script and MSAL auth.
	// DO NOT embed credentials for administrative or production accounts. 
	std::string userName = "";

	// Create the mip::ApplicationInfo object. 

	// Friendly Name should be the name of the application as it should appear in reports.
	mip::ApplicationInfo appInfo{ clientId,  "MIP SDK Protection Sample for C++", "1.10.0" };

	// All actions for this tutorial project are implemented in samples::policy::Action
	// Source files are Action.h/cpp.	
	// Action's constructor takes in the mip::ApplicationInfo object and uses the client ID for auth.
	// Username and password are required in this sample as the oauth2 token is obtained via Python script and basic auth.
	Action action = Action(appInfo, userName);

	while (true)
	{
		string choice;

		cout << "Input 1 for encrypting a string and 2 for decrypting" << endl;
		cout << endl << "Choice: ";
		cin >> choice;

		if (choice == "1")
		{
			encryptString(action);
		}
		else if (choice == "2") {
			decryptString(action);
		}
	}
		
	return 0;
}

inline void printVector(std::vector<uint8_t>& vector) {
	std::string str(vector.begin(), vector.end());
	cout << endl << "Print vector :" << endl << str << endl;
}

inline int encryptString(sample::protection::Action& action) {
	// local variables to store target file and the label that will be applied to the file.
	string templateToApply;
	string plaintext;
	string cipherText;
	std::vector<uint8_t> publishingLicense;

	templateToApply = "";

	// Call action.ListLabels() to display all available labels, then pause.
	cout << "*** Template List: " << endl;
	action.ListTemplates();

	// Prompt the user to copy the Label ID from a displayed label. This will be stored
	// then applied later to a file.		
	cout << "Copy a template ID from above to apply to a new string or q to quit." << endl;
	cout << endl << "Template ID: ";
	cin >> templateToApply;

	if (templateToApply == "q")
	{
		return 0;
	}

	// Generate a new protection descriptor and store publishing license
    // Prompt the user to enter a file. A labeled copy of this file will be created.
	cout << "Enter some text to encrypt: ";
	std::getline(std::cin >> std::ws, plaintext);

	// Show action plan
	cout << "Applying Label ID " + templateToApply + " to: " << endl << plaintext << endl;

	publishingLicense = action.ProtectString(plaintext, cipherText, templateToApply);
	cout << "Protected output: " << endl << cipherText + "|End" << endl;

	// save license in file
	write_vector_to_disk("MIPLicense.txt", publishingLicense);

	system("pause");
}

inline void decryptString(sample::protection::Action &action) {
	string cipherText;
	string decryptedText;
	std::vector<uint8_t> publishingLicense;

	publishingLicense = read_vector_from_disk("MIPLicense.txt");

	cout << endl << "Enter text to decrypt: ";
	cin >> cipherText;

	// Use the same PL to decrypt the ciphertext.
	action.DecryptString(decryptedText, cipherText, publishingLicense);

	// Output decrypted content. Should match original input text.
	cout << endl << "Decrypted string: " << decryptedText << endl;

	system("pause");
}

inline std::vector<uint8_t> read_vector_from_disk(std::string file_path)
{
	std::ifstream instream(file_path, std::ios::in | std::ios::binary);
	std::vector<uint8_t> data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());
	instream.close();
	return data;
}

inline void write_vector_to_disk(std::string file_path, std::vector<uint8_t> &publishingLicense)
{
	// remove previous file
	std::remove((const char*) &file_path);

	// save license in file
	std::ofstream outfile(file_path, std::ios::out | std::ios::binary);
	outfile.write((const char*)&publishingLicense[0], publishingLicense.size());
	outfile.close();
}

