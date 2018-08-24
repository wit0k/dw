**MacOS**:

If you encounter issues with your brew installation, you might follow the procedure below:

* Uninstall brew: /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/uninstall)"
* Install brew: /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
* Update brew: brew update

CAUTION: IT WOULD UNINSTALL PACKAGES INSTALLED BY brew!

Virtual environment:

which python3
virtualenv -p /Library/Frameworks/Python.framework/Versions/3.6/bin/python3 dw
source dw/bin/activate

Install dependencies:

* brew install tesseract
* brew install libmagic

* pip install -U pip
* pip install -U setuptools
* pip install bs4
* pip install python-magic
* pip install Pillow
* pip install requests
* pip install simplejson
* pip install pytesseract
* pip install pysmb
* pip install dnspython
* pip install iocextract

I will create requirements.txt and setup script when time allows