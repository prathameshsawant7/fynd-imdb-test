from datetime import datetime
from elasticsearch import Elasticsearch
from app import app


es = Elasticsearch([app.config['ELASTICSEARCH_URL']]) \
    if app.config['ELASTICSEARCH_URL'] else None


class ESOperations:
    def __init__(self, index):
        """
        :param index: Declare index for Elasticsearch
        """
        self.index = index

    def create_document(self, data):
        """
        To create document in Elasticsearch
        :param data: Data to push in Elasticsearch
        :return: None
        """
        slug = data['id']
        title = data['name']
        content = data
        body = {
            'slug': slug,
            'title': title,
            'content': content,
            'timestamp': datetime.now()
        }
        es.index(index=self.index, doc_type='title', id=slug, body=body)

    def delete_document(self, data):
        """
        Delete document from Elasticsearch
        :param data: Dictionary containing document ID field
        :return: None
        """
        es.delete(index=self.index, doc_type="title", id=data['id'])

    def update_document(self, data):
        """
        Delete existing document and create new document with updated data
        :param data: Data to Update
        :return: None
        """
        self.delete_document(data)
        self.create_document(data)

    def search_document(self, keyword, filters):
        """
        Search on Elasticsearch Index
        :param keyword: keyword to search
        :param filters: filters on search
        :return: Dict of searched result set.
        """
        body = {
            "query": {}
        }
        if not keyword:
            body['query']['match_all'] = {"boost": 1.2}
        else:
            body['query'] = {
                "multi_match": {
                    "query": keyword,
                    "operator": "OR",
                    "type": "phrase_prefix",
                    "max_expansions": 50,
                    "fields": ["content", "title"]
                }
            }

        body['size'] = 40
        return es.search(index=self.index, doc_type="title", body=body)




