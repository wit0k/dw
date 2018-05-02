from io import BytesIO
from io import TextIOWrapper

from smb.SMBConnection import SMBConnection # pip install pysmb
from smb import smb_structs

class smb(object):

    def __init__(self):
        pass

    def connect(self, remote_server, path, user="Guest", password=""):
        conn = SMBConnection(user,
                             password,
                             remote_server,
                             path,
                             use_ntlm_v2=True)

        try:
            # Check of tieout is possible...
            conn.connect(remote_server, 139)
            with open('local_file', 'wb') as fp:
                # conn.retrieveFile('share', '/path/to/remote_file', fp)
                results = conn.listPath('media_source', '/')
                filenames = [(r.filename, r.isDirectory) for r in results]

                for r in results:

                    if r.isDirectory == False:

                        temp_fh = open("wsf.txt", "wb")

                        file_attributes, filesize = conn.retrieveFile('media_source', '/' + r.filename, temp_fh)

                        temp_fh.write()

                        temp_fh.close()

                "Think what to do with . and .."
                for f in filenames:
                    print(f)

                test = ""
                # documents
        except Exception as msg:
            pass


