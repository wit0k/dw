# dw (Downloader) [BETA]

**Features**:

<pre>Parsing URL: hxxp://2k20[.]tk/ to: http://2k20.tk/
Parsing URL: http[:]//120.132.17[.]180:66/ to: http://120.132.17.180:66/</pre>

* Accepts basic URL obfuscation which gets automatically resolved
* Built-in links/hrefs detection
* Bulk file downloads 
* Automatic compression 
* Vendor submission

**Use cases:**

<pre> dw.py -z -gl -i urls.txt </pre>

* Load and deobfuscate URLs from input file (url.txt) [-i < filer >]
* Retrieve all available links/hrefs from loaded URLs [-gl]
* Download all detected links/hrefs [If --skip-download not specified]
* Compress downloaded files and save in archive/ folder (Default 9 files by zip archive) [-z]

<pre> dw.py -gl --submit -i urls.txt </pre>

* Additionally submits compressed archives to configured vendors [--submit enables -z automatically]

<pre> dw.py -z -i downloads/ </pre>

* Load all files from input folder (downloads/) [-i < folder >]
* Compress all files from input folder and saves them to archive/ folder [-z]

<pre> dw.py --submit -i downloads/ </pre>

* Process files from downloads/ [zip them when necessary]
* Processed/compressed files are saved into archive/ folder
* Submits files from archive/ folder to configured vendors [--submit enables -z automatically]
