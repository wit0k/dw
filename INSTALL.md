**MacOS**:

If you encounter issues with your brew installation, you might follow the procedure below:

* Uninstall brew: /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/uninstall)"
* Install brew: /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
* Update brew: brew update

CAUTION: IT WOULD UNINSTALL PACKAGES INSTALLED BY brew!
 
Install dependencies:

* brew install tesseract
* brew install libmagic
* pip install bs4
* pip install python-magic
* pip install Pillow
* pip install requests
* pip install simplejson
* pip install pytesseract
* ...

I will create requirements.txt and setup script when time allows