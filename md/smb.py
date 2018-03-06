from smb.SMBConnection import SMBConnection
from smb import smb_structs

class smb(object):

    def __init__(self):
        pass

    def connect(self, remote_server, user="Guest", password=""):
        conn = SMBConnection(user,
                             password,
                             remote_server,
                             'SERVER',
                             use_ntlm_v2=True)

        try:
            # Check of tieout is possible...
            conn.connect(remote_server, 139)
            with open('local_file', 'wb') as fp:
                # conn.retrieveFile('share', '/path/to/remote_file', fp)
                results = conn.listPath('/docs', '/')
                filenames = [(r.filename, r.isDirectory) for r in results]
                test = ""
                # documents
        except Exception as msg:
            pass


