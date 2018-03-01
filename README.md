# dw [BETA]

**Description**:

The tool has been created to speed up manual malware hunting tasks. A simple example is already covered in **“Use cases”** but let’s describe it verbally.
Imagine following situation, you found an open directory on the Internet, which is full of malicious samples (Example below)

![Open directoryąć](http://regenerus.com/download/2k20.jpg)

Normally to download these files you would have to manually save them (or retrieve the page source code and pull the href elements with regex or so, and then download them with curl or wget). When the amount of files is bigger than few it becomes unmanageable and simple waste of time. 

The “dw” if instructed to do so, could crawl the site for all available href elements and reconstruct their full URLs properly. The list of retrieved URLs could be automatically downloaded; or you could stop at this stage and decide to modify the list etc. The downloaded files could be compressed (zipped) and eventually automatically submitted to Antivirus vendor.

The tool is quite granular: 
* You could decide to only crawl for href elements from given URL(s) or to directly download URLs indicated in the input file.
* You could only compress downloaded files 
* You could only submit files from given folder to Antivirus vendor


**Features**:

* Accepts basic URL obfuscation which gets automatically resolved
  <pre>
  urls.txt:
    hxxp://2k20[.]tk/
    http[:]//120.132.17[.]180:66/ </pre>
  <pre>
  Parsing URL: hxxp://2k20[.]tk/ to: http://2k20.tk/
  Parsing URL: http[:]//120.132.17[.]180:66/ to: http://120.132.17.180:66/
  </pre>
* Built-in links/hrefs detection
  <pre>Getting hrefs from: http://2k20.tk/
  http://2k20.tk//0199.doc
  http://2k20.tk//1.exe
  http://2k20.tk//1.hta
  http://2k20.tk//1.rar
  http://2k20.tk//1.zip
  http://2k20.tk//8570.docx
  http://2k20.tk//8759.doc
  http://2k20.tk//a.apk
  http://2k20.tk//doc.doc</pre>
* Bulk file downloads 
  <pre>URL Download -> SUCCESS -> [HTTP200] - URL: http://2k20.tk//0199.doc
  [sha256: fe48b06516bf8939fe6b72808520435a98ec29fcbff9a324842c14abb10ec489] - downloads//0199.doc
  URL Download -> SUCCESS -> [HTTP200] - URL: http://2k20.tk//1.exe
  [sha256: 7b873da42a24ef30d6f523411f40c593a401ebfc9461cc3d93058c8ab8659225] - downloads//1.exe
  URL Download -> SUCCESS -> [HTTP200] - URL: http://2k20.tk//1.hta
  [sha256: b8397dac9b00dabcc65e0bf0505c74a134d570674829e901cf10bd4a047db09f] - downloads//1.hta
  URL Download -> SUCCESS -> [HTTP200] - URL: http://2k20.tk//1.rar
  [sha256: 9ac47bd4e34cc77a2abc3eb7d62dbb246312c748f4e39cd5351cc84022878424] - downloads//1.rar</pre>
* Automatic compression
  <pre>Add 'downloads//0199.doc' to: 'archive/samples-1.zip'
  Add 'downloads//1.exe' to: 'archive/samples-1.zip'
  Add 'downloads//1.hta' to: 'archive/samples-1.zip'
  Add 'downloads//1.rar' to: 'archive/samples-1.zip'</pre>
* Vendor submission (Requires specific config/%vendonr_name%.vd file)
  <pre>submit - Submitting: archive/samples-2.zip to: https://...
  submit - Submission OK -> archive/samples-2.zip</pre>
* Recursive < a href > crawling: 
    <pre> 
    Getting hrefs from: http://109.234.36.233/bot
    All retrieved HREFs:
    http://109.234.36.233/bot/
    http://109.234.36.233/bot/.vs/
    http://109.234.36.233/bot/.vs/LoaderBot/
    ...
    http://109.234.36.233/bot/Miner/bin/Release/LoaderBot.vshost.exe
    http://109.234.36.233/bot/Miner/bin/Release/LoaderBot.vshost.exe.config
    http://109.234.36.233/bot/Miner/bin/Release/LoaderBot.vshost.exe.manifest
    ...
  </pre>  

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

<pre> dw.py -i urls.txt -r --skip-download </pre> 

<span style="color:#FF0000"> Use with caution!!! </span>

* Retrieve all available links/hrefs from loaded URLs (Recursively) 
* Automatically enables -gl mode 
* Skip the download action

**Command Line:**

<pre>
optional arguments:
  -h, --help            show this help message and exit

Script arguments:

  -i INPUT, --input INPUT
                        Load and deobfuscate URLs from input file, or load
                        files from given folder for further processing
  -d DOWNLOAD_FOLDER, --download-folder DOWNLOAD_FOLDER
                        Specify custom download folder location (Default:
                        downloads/
  -a ARCHIVE_FOLDER, --archive ARCHIVE_FOLDER
                        Specify custom archive folder location (Default:
                        'archive/')
  -o OUTPUT_DIRECTORY   Copy loaded/deduplicated files into specified output
                        directory (Applicable when -dd is used)
  -dd, --dedup          Deduplicate the input and downloaded files
  -gl, --get-links      Retrieve all available links/hrefs from loaded URLs
  -rl, --recursive-hostonly
                        Enable recursive crawling (Applies to -gl), but crawl
                        for hrefs containing the same url host as input url
                        (Sets --recursion-depth 0 and enables -gl)
  -r, --recursive       Enable recursive crawling (Applies to -gl)
  -ui, --url-info       Retrieve URL information from supported vendors for
                        all loaded input URLs.
  -uif, --url-info-force
                        Force url info lookup for every crawled URL (NOT
                        recommended)
  --skip-download       Skips the download operation
  -z, --zip             Compress all downloaded files, or files from input
                        folder (If not zipped already)
  --submit              Submit files to AV vendors (Enables -z by default)
  -v VERBOSE_LEVEL, --verbose VERBOSE_LEVEL
                        Set the logging level to one of following: INFO,
                        WARNING, ERROR or DEBUG (Default: WARNING)
  --debug-requests      Sends GET/POST requests via local proxy server
                        127.0.0.1:8080

Custom arguments:

  -rd RECURSION_DEPTH, --recursion-depth RECURSION_DEPTH
                        Max recursion depth level for -r option (Default: 20)
  --limit-archive-items MAX_FILE_COUNT_PER_ARCHIVE
                        Sets the limit of files per archive (Default: 9). [0 =
                        Unlimited]
  -sc SUBMISSION_COMMENTS, --submission-comments SUBMISSION_COMMENTS
                        Insert submission comments (Default: <archive_name>)
</pre>
 
**Change log:**

Ver. 0.0.8:

* -r, --recursive: Enable recursive crawling
* -rd, --recursion-depth: Max recursion depth level (default: 20)
* Simplified get_hrefs() code
* get_hrefs will use the requests session object and mix of HEAD and GET requests to speed up crawling performance
* get_hrefs set to return unique hrefs only 

Ver. 0.0.9:

* Fixes to download and get_hrefs functions
* If verbose level is set to DEBUG, print the href every time it's added to links list 
* Documentation update 

Ver. 0.1.0:

* Fixes to get_hrefs function
* "-rl", "--recursive-hostonly". Would crawl webistes which have the same url host as the input URL (Recommended)
* Small error handling to showing archive content (Didn't work for .jar files)
* Fix to download function (it was corrupting files)
* Documentation update

Ver. 0.1.1:

* Fix to download function (it was corrupting files)
* Documentation update

Ver. 0.1.2:

* Fix to download function (Logic imrpoved)

Ver. 0.1.3:

* Supressed the warning: urllib3/connectionpool.py:852: InsecureRequestWarning: Unverified HTTPS request is being made

Ver. 0.1.4:

* Critical fix to get_hrefs (Automatic parent folder and mod_autoindex detection; preventing back loops).

Ver. 0.1.5:

* Detect and skip links automatically created in open directory like: Name, Last modified, Size, Description

Ver. 0.1.7:

* Slight logic change to tasks execution 
* New parameters for input and downloaded files deduplication and copying files to an output folder 
* BC proxy lookup support
* uniq class for handling deduplication 
* Submitter class (so far for proxy lookup only, but soon for VT as well)

Ver. 0.1.7:

* If DEBUG mode enabled, it would print detected href's mime type if such was directly sent by the server 
* Download function prints detailed info about downloaded file like:  file_hash,file_destination,file_mime_type,proxy_category,url 

Ver. 0.1.9:

* Params names and documentation update



