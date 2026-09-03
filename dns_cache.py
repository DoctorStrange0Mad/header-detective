import json
import os
import dns.resolver

_original_resolve = dns.resolver.resolve
_cache = {}

def get_cache_key(domain, record_type):
    return f"{domain.lower()}:{record_type.upper()}"

def populate_cache(domain, record_type, answers_list):
    key = get_cache_key(domain, record_type)
    _cache[key] = answers_list

class CachedAnswer:
    def __init__(self, strings):
        self.strings = [s.encode('utf-8') for s in strings]

def resolve(domain, record_type='TXT', lifetime=3.0):
    key = get_cache_key(domain, record_type)
    
    if key in _cache:
        answers_list = _cache[key]
        if answers_list is None:
            raise dns.resolver.NXDOMAIN
            
        return [CachedAnswer(strings) for strings in answers_list]
        
    try:
        answers = _original_resolve(domain, record_type, lifetime=lifetime)
        
        # Populate cache
        cache_data = []
        for rdata in answers:
            if hasattr(rdata, 'strings'):
                strings = [s.decode('utf-8') for s in rdata.strings]
                cache_data.append(strings)
        
        _cache[key] = cache_data
        return answers
    except dns.resolver.NXDOMAIN as e:
        _cache[key] = None
        raise e
    except Exception as e:
        raise e
