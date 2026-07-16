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


#include "utils.h"
#include <fstream>
#include <string>

using std::ifstream;
using std::string;

static const char kPathSeparatorWindows = '\\';
static const char kPathSeparatorUnix = '/';
static const char kExtensionSeparator = '.';
static const char kPathSeparatorCStringWindows[] = { kPathSeparatorWindows, '\0' };
static const char kPathSeparatorCStringUnix[] = { kPathSeparatorUnix, '\0' };
static const char kPathSeparatorsAll[] = { kPathSeparatorWindows, kPathSeparatorUnix, '\0' };

namespace sample {	
	namespace utils {
		bool FileExists(const char* path) {
			ifstream file(path);
			return file.good();
		}

		string GetFileExtension(const string& filePath) {
			string fileName = GetFileName(filePath);
			auto index = fileName.rfind(kExtensionSeparator);
			if (index == string::npos) return "";
			return fileName.substr(index); // Include the dot in the file extension
		}

		string GetFileName(const string& filePath) {
			auto index = filePath.find_last_of(kPathSeparatorsAll);
			if (index == string::npos) return filePath;
			return filePath.substr(index + 1);
		}

		string GetOutputFileNameModified(const string& input, const string& modification)
		{
			auto result = input;
			auto fileExtension = sample::utils::GetFileExtension(result);
			auto resultWithoutExtension = result.substr(0, result.length() - fileExtension.length());
			return resultWithoutExtension + modification + fileExtension;			
		}
	}
} // namespace