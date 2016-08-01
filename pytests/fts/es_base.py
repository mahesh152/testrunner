import httplib2
import json
from tasks.taskmanager import TaskManager
from tasks.task import *

class BLEVE:
    STOPWORDS = ['i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves',
                 'you', 'your', 'yours', 'yourself', 'yourselves', 'he', 'him',
                 'his', 'himself', 'she', 'her', 'hers', 'herself', 'it', 'its',
                 'itself', 'they', 'them', 'their', 'theirs', 'themselves',
                 'what', 'which', 'who', 'whom', 'this', 'that', 'these',
                 'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been',
                 'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did',
                 'doing', 'would', 'should', 'could', 'ought', "i'm", "you're",
                 "he's", "she's", "it's", "we're", "they're", "i've", "you've",
                 "we've", "they've", "i'd", "you'd", "he'd", "she'd", "we'd",
                 "they'd", "i'll", "you'll", "he'll", "she'll", "we'll",
                 "they'll", "isn't", "aren't", "wasn't", "weren't", "hasn't",
                 "haven't", "hadn't", "doesn't", "don't", "didn't", "won't",
                 "wouldn't", "shan't", "shouldn't", "can't", 'cannot',
                 "couldn't", "mustn't", "let's", "that's", "who's", "what's",
                 "here's", "there's", "when's", "where's", "why's", "how's",
                 'a', 'an', 'the', 'and', 'but', 'if', 'or', 'because', 'as',
                 'until', 'while', 'of', 'at', 'by', 'for', 'with', 'about',
                 'against', 'between', 'into', 'through', 'during', 'before',
                 'after', 'above', 'below', 'to', 'from', 'up', 'down', 'in',
                 'out', 'on', 'off', 'over', 'under', 'again', 'further',
                 'then', 'once', 'here', 'there', 'when', 'where', 'why',
                 'how', 'all', 'any', 'both', 'each', 'few', 'more', 'most',
                 'other', 'some', 'such', 'no', 'nor', 'not', 'only', 'own',
                 'same', 'so', 'than', 'too', 'very']

    STD_ANALYZER = {
        "settings": {
            "analysis": {
                "analyzer": {
                    "default": {
                        "type":      "standard",
                        "stopwords": STOPWORDS
                    }
                }
            }
        }
    }

    CUSTOM_ANALYZER = {
        "settings": {
            "analysis": {
                "analyzer": {
                }
            }
        }
    }

    FTS_ES_ANALYZER_MAPPING = {
        "char_filters" : {
            "html":"html_strip",
            "zero_width_spaces":"html_strip"
        },
        "token_filters": {
            "apostrophe":"apostrophe",
            "elision_fr":"elision",
            "to_lower":"lowercase"
        },
        "tokenizers": {
            "letter":"letter",
            "web":"uax_url_email",
            "whitespace":"whitespace",
            "unicode":"standard",
            "single":"standard"
        }
    }

class ElasticSearchBase(object):

    def __init__(self, host, logger):
        #host is in the form IP address
        self.__log = logger
        self.__host = host
        self.__document = {}
        self.__mapping = {}
        self.__STATUSOK = 200
        self.__indices = []
        self.__index_types = {}
        self.__connection_url = 'http://{0}:{1}/'.format(self.__host.ip,
                                                        self.__host.port)
        self.es_queries = []
        self.task_manager = TaskManager("ES_Thread")
        self.task_manager.start()
        self.http = httplib2.Http

    def _http_request(self, api, method='GET', params='', headers=None,
                      timeout=30):
        if not headers:
            headers = {'Content-Type': 'application/json',
                       'Accept': '*/*'}
        try:
            response, content = httplib2.Http(timeout=timeout).request(api,
                                                                       method,
                                                                       params,
                                                                       headers)
            if response['status'] in ['200', '201', '202']:
                return True, content, response
            else:
                try:
                    json_parsed = json.loads(content)
                except ValueError as e:
                    json_parsed = {}
                    json_parsed["error"] = "status: {0}, content: {1}".\
                        format(response['status'], content)
                reason = "unknown"
                if "error" in json_parsed:
                    reason = json_parsed["error"]
                self.__log.error('{0} error {1} reason: {2} {3}'.format(
                    api,
                    response['status'],
                    reason,
                    content.rstrip('\n')))
                return False, content, response
        except socket.error as e:
            self.__log.error("socket error while connecting to {0} error {1} ".
                             format(api, e))
            raise ServerUnavailableException(ip=self.__host.ip)

    def is_running(self):
        """
         make sure ES is up and running
         check the service is running , if not abort the test
        """

        try:
            status, content, _ = self._http_request(
                self.__connection_url,
                'GET')
            if status:
                return True
            else:
                return False
        except Exception as e:
            raise e

    def delete_index(self, index_name):
        """
        Deletes index
        """
        try:
            url = self.__connection_url + index_name
            status, content, _ = self._http_request(url, 'DELETE')
        except Exception as e:
            raise e

    def delete_indices(self):
        """
        Delete all indices present
        """
        for index_name in self.__indices:
            self.delete_index(index_name)
            self.__log.info("ES index %s deleted" % index_name)

    def create_empty_index(self, index_name):
        """
        Creates an empty index, given the name
        """
        try:
            self.delete_index(index_name)
            status, content, _ = self._http_request(
                self.__connection_url + index_name,
                'PUT')
            if status:
                self.__indices.append(index_name)
        except Exception as e:
            raise Exception("Could not create ES index : %s" % e)

    def create_empty_index_with_bleve_equivalent_std_analyzer(self, index_name):
        """
        Refer:
        https://www.elastic.co/guide/en/elasticsearch/guide/current/
        configuring-analyzers.html
        """
        try:
            self.delete_index(index_name)
            status, content, _ = self._http_request(
                self.__connection_url + index_name,
                'PUT', json.dumps(BLEVE.STD_ANALYZER))
            if status:
                self.__indices.append(index_name)
        except Exception as e:
            raise Exception("Could not create index with ES std analyzer : %s"
                            % e)

    def create_index_mapping(self, index_name, es_mapping, fts_mapping=None):
        """
        Creates a new default index, with the given mapping
        """
        self.delete_index(index_name)

        if not fts_mapping:
            map = {"mappings": es_mapping, "settings": BLEVE.STD_ANALYZER['settings']}
        else :
            # Find the ES equivalent char_filter, token_filter and tokenizer
            es_settings = self.populate_es_settings(fts_mapping['params']
                                                    ['mapping']['analysis']['analyzers'])

            # Create an ES custom index definition
            map = {"mappings": es_mapping, "settings": es_settings['settings']}

        # Create ES index
        try:
            self.__log.info("Creating %s with mapping %s"
                            % (index_name, json.dumps(map, indent=3)))
            status, content, _ = self._http_request(
                self.__connection_url + index_name,
                'PUT',
                json.dumps(map))
            if status:
                self.__log.info("SUCCESS: ES index created with above mapping")
            else:
                raise Exception("Could not create ES index")
        except Exception as e:
            raise Exception("Could not create ES index : %s" % e)

    def populate_es_settings(self, fts_custom_analyzers_def):
        """
        Populates the custom analyzer defintion of the ES Index Definition.
        Refers to the FTS Custom Analyzers definition and creates an
            equivalent definition for each ES custom analyzer
        :param fts_custom_analyzers_def: FTS Custom Analyzer Definition
        :return:
        """

        num_custom_analyzers = len(fts_custom_analyzers_def)
        n = 1
        analyzer_map = {}
        while n <= num_custom_analyzers:
            customAnalyzerName = fts_custom_analyzers_def.keys()[n-1]
            fts_char_filters = fts_custom_analyzers_def[customAnalyzerName]["char_filters"]
            fts_tokenizer = fts_custom_analyzers_def[customAnalyzerName]["tokenizer"]
            fts_token_filters = fts_custom_analyzers_def[customAnalyzerName]["token_filters"]

            analyzer_map[customAnalyzerName] = {}
            analyzer_map[customAnalyzerName]["char_filter"] = []
            analyzer_map[customAnalyzerName]["filter"] = []
            analyzer_map[customAnalyzerName]["tokenizer"] = ""

            for fts_char_filter in fts_char_filters:
                analyzer_map[customAnalyzerName]['char_filter'].append( \
                    BLEVE.FTS_ES_ANALYZER_MAPPING['char_filters'][fts_char_filter])

            analyzer_map[customAnalyzerName]['tokenizer'] = \
                BLEVE.FTS_ES_ANALYZER_MAPPING['tokenizers'][fts_tokenizer]

            for fts_token_filter in fts_token_filters:
                analyzer_map[customAnalyzerName]['filter'].append( \
                    BLEVE.FTS_ES_ANALYZER_MAPPING['token_filters'][fts_token_filter])

            n += 1

        analyzer = BLEVE.CUSTOM_ANALYZER
        analyzer['settings']['analysis']['analyzer'] = analyzer_map
        return analyzer

    def create_alias(self, name, indexes):
        """
        @name: alias name
        @indexes: list of target indexes
        """
        try:
            self.__log.info("Checking if ES alias '{0}' exists...".format(name))
            self.delete_index(name)
            alias_info = {"actions": []}
            for index in indexes:
                alias_info['actions'].append({"add": {"index": index,
                                                      "alias": name}})
            self.__log.info("Creating ES alias '{0}' on {1}...".format(
                name,
                indexes))
            status, content, _ = self._http_request(
                self.__connection_url + "_aliases",
                'POST',
                json.dumps(alias_info))
            if status:
                self.__log.info("ES alias '{0}' created".format(name))
                self.__indices.append(name)
        except Exception as ex:
            raise Exception("Could not create ES alias : %s" % ex)

    def async_load_ES(self, index_name, gen, op_type='create'):
        """
        Asynchronously run query against FTS and ES and compare result
        note: every task runs a single query
        """

        _task = ESLoadGeneratorTask(es_instance=self,
                                    index_name=index_name,
                                    generator=gen,
                                    op_type=op_type)
        self.task_manager.schedule(_task)
        return _task

    def async_bulk_load_ES(self, index_name, gen, op_type='create', batch=5000):
        _task = ESBulkLoadGeneratorTask(es_instance=self,
                                    index_name=index_name,
                                    generator=gen,
                                    op_type=op_type,
                                    batch=batch)
        self.task_manager.schedule(_task)
        return _task

    def load_bulk_data(self, filename):
        """
        Bulk load to ES from a file
        curl -s -XPOST 172.23.105.25:9200/_bulk --data-binary @req
        cat req:
        { "index" : { "_index" : "default_es_index", "_type" : "aruna", "_id" : "1" } }
        { "field1" : "value1" , "field2" : "value2"}
        { "index" : { "_index" : "default_es_index", "_type" : "aruna", "_id" : "2" } }
        { "field1" : "value1" , "field2" : "value2"}
        """
        try:
            import os
            url = self.__connection_url + "/_bulk"
            data = open(filename, "rb").read()
            status, content, _ = self._http_request(url,
                                                    'POST',
                                                    data)
            return status
        except Exception as e:
            raise e

    def load_data(self, index_name, document_json, doc_type, doc_id):
        """
        index_name : name of index into which the doc is loaded
        document_json: json doc
        doc_type : type of doc. Usually the '_type' field in the doc body
        doc_id : document id
        """
        try:
            url = self.__connection_url + index_name + '/' + doc_type + '/' +\
                  doc_id
            status, content, _ = self._http_request(url,
                                                    'POST',
                                                    document_json)
        except Exception as e:
            raise e

    def update_index(self, index_name):
        """
        This procedure will refresh index when insert is performed .
        Need to call this API to take search in effect.
        :param index_name:
        :return:
        """
        try:
            status, content, _ = self._http_request(
                self.__connection_url + index_name +'/_refresh',
                'POST')
        except Exception as e:
            raise e

    def search(self, index_name, query, result_size=1000000):
        """
           This function will be used for search . based on the query
           :param index_name:
           :param query:
           :return: number of matches found, doc_ids and time taken
        """
        try:
            doc_ids = []
            url = self.__connection_url + index_name + '/_search?size='+ \
                  str(result_size)
            status, content, _ = self._http_request(
                url,
                'POST',
                json.dumps(query))
            if status:
                content = json.loads(content)
                for doc in content['hits']['hits']:
                    doc_ids.append(doc['_id'])
                return content['hits']['total'], doc_ids, content['took']
        except Exception as e:
            self.__log.error("Couldn't run query on ES: %s, reason : %s"
                             % (json.dumps(query), e))
            raise e

    def get_index_count(self, index_name):
        """
         Returns count of docs in the index
        """
        try:
            status, content, _ = self._http_request(
                self.__connection_url + index_name + '/_count',
                'POST')
            if status:
                return json.loads(content)['count']
        except Exception as e:
            raise e

    def get_indices(self):
        """
        Return all the indices created
        :return: List of all indices
        """
        return self.__indices
