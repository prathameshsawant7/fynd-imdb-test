import json
from datetime import datetime
from elasticsearch import Elasticsearch
from app import app


es = Elasticsearch([app.config['ELASTICSEARCH_URL']]) \
    if app.config['ELASTICSEARCH_URL'] else None


class ESOperations:
    def __init__(self, index):
        self.index = index

    def create_document(self, data):
        slug = data['id']
        title = data['name']
        content = json.dumps(data)
        body = {
            'slug': slug,
            'title': title,
            'content': content,
            'timestamp': datetime.now()
        }
        es.index(index=self.index, doc_type='title', id=slug, body=body)

    def delete_document(self, data):
        es.delete(index=self.index, doc_type="title", id=data['id'])

    def update_document(self, data):
        self.delete_document(data)
        self.create_document(data)

    def search_document(self, keyword):
        body = {
            "query": {
                "multi_match": {
                    "query": keyword,
                    "operator": "OR",
                    "type": "phrase_prefix",
                    "max_expansions": 500,
                    "fields": ["content", "title"]
                }
            },
            "size": 40,
        }
        return es.search(index=self.index, doc_type="title", body=body)




