import os.path
import logging
import sqlite3

logger = logging.getLogger('dw')

class handler(object):

    def __init__(self, database_obj):

        self.db = None

        if not isinstance(database_obj, database):
            logger.error("The handler class requires database() object to initialize")
        else:
            self.db = database_obj


    def _dict_to_query(self, query_data, query_type, table_name):

        query = None

        if query_data:

            """ Create new dict only with keys having none empty values """
            f_query_data = {k: v for k, v in query_data.items() if v is not None}

            if f_query_data:
                """ Get fields and values  """
                str_fields = ",".join(f_query_data.keys())
                t_values = tuple(f_query_data.values())
                schema_values = '{}'.format(', '.join('?' * len(f_query_data.values())))

                if query_type == "INSERT":
                    query = f"INSERT INTO {table_name}({str_fields}) VALUES({schema_values})"
                    return query, t_values

                elif query_type == "UPDATE":
                    query = f"UPDATE {table_name} SET rating = ? WHERE name = ?"
                    return query, t_values

                else:
                    """ Unsupported query type """
                    return query, t_values
            else:
                logger.error("Query data has only Null values. Cancel query creation")
                return query, None

        else:
            """ No query data specified """
            return query, None


    def insert(self, sample_obj, sample_type="url"):
        """ Insert dw objects into a local database """

        update_sample = False

        """ Check if obj is present in samples table  """
        if sample_type == "url":
            query_check = f'SELECT url FROM samples WHERE url="{sample_obj.url}"'

        result = self.db.query(query_check)

        if result:
            logger.debug("Updating existing records")
            update_sample = True

        """ Update existing record """
        if update_sample:
            pass
        else:
            """ Create new record """
            # Table: samples
            query_insert_data = {
                "submission_time": sample_obj.time_created,
                "hash": sample_obj.hash,
                "url": sample_obj.url,
                "type": sample_type,
                "file": sample_obj.file
            }

            query_insert, values = self._dict_to_query(query_insert_data, "INSERT", "samples")
            self.db.query(query_insert, values)


        self.db.close()
        test = ""


class database(object):

    def __init__(self, file):

        self.connection = None
        self.file = None
        self.config = ("PRAGMA synchronous = OFF;",
                       "PRAGMA journal_mode = OFF;",
                       "PRAGMA locking_mode = OFF;",  # https://sqlite.org/tempfiles.html
                       "PRAGMA temp_store = MEMORY;",
                       "PRAGMA count_changes = OFF;",
                       "PRAGMA PAGE_SIZE = 4096;",
                       "PRAGMA default_cache_size=700000;",
                       "PRAGMA cache_size=700000;",
                       "PRAGMA compile_options;")

        if not file:
            logger.error("Database file cannot be null")

        if os.path.isfile(file):
            self.file = file
            self.connection = self.open(file)
        else:
            logger.warning(f"File not found: ({file})")
            logger.info(f"Creating new database")
            self.connection = self.create(file)

    def open(self, file):
        try:
            logger.debug("Connecting to: %s" % file)
            if self.connection and file == self.file:
                logger.debug("Returning existing connection object")
                return self.connection
            else:
                logger.debug("Creating new connection object")
                return sqlite3.connect(file)

        except Exception as e:
            logger.error(f"ERROR: db() ->  connect({self.file}) -> Msg: {str(e.message)}")
            return None

    def query(self, query, values=None):

        if self.connection:
            try:

                self.connection.row_factory = sqlite3.Row
                cursor_object = self.connection.cursor()

                if values:
                    result = cursor_object.execute(query, values)
                else:
                    result = cursor_object.execute(query)

                if 'INSERT' in query:
                    self.connection.commit()
                else:
                    rows = result.fetchall()
                    return rows

            except Exception as e:
                logger.error(f"ERROR: db() ->  query({query}) -> Msg: {str(e)}")
                return None

    def close(self):
        try:
            self.connection.commit()
            self.connection.close()
        except Exception as e:
            logger.error(f"ERROR: db() ->  close({self.file}) -> Msg: {str(e.message)}")
            return None

    def create(self, file):

        if os.path.isfile(file):
            logger.error("The database: %s already exist.")
            return None

        try:
            logger.info("Creating new database: %s" %file)

            con = self.open(file)
            cur = con.cursor()

            """ Configure the database """
            for _statement in self.config:
                cur.execute(_statement)

            """ Create SQL Tables: """
            # Samples
            cur.execute(
                '''CREATE TABLE samples(submission_time TEXT, hash TEXT, url TEXT, type TEXT, file TEXT)'''
            )
            # Proxy Submissions
            cur.execute(
                '''CREATE TABLE proxy_submissions(submission_time TEXT, hash TEXT, url TEXT, provider TEXT, 
                category TEXT)'''
            )
            # AV_Submissions
            cur.execute(
                '''CREATE TABLE av_submissions(submission_time TEXT, hash TEXT, url TEXT, tracking_id TEXT, 
                detection_name TEXT)'''
            )
            # VT_Submissions
            cur.execute(
                '''CREATE TABLE vt_submissions(submission_time TEXT, hash TEXT, url TEXT, tracking_url TEXT, 
                score TEXT, detection_rate TEXT, result TEXT)'''
            )
            # NET_Info
            cur.execute(
                '''CREATE TABLE netinfo(submission_time TEXT, hash TEXT, url TEXT, domain TEXT, 
                ip TEXT, hosting_provider TEXT)'''
            )

            con.commit()
            logger.info("Database created")
            self.file = file
            return con

        except Exception as e:
            logger.error(f"create({file}) -> Msg: {str(e.message)}")
            return None
