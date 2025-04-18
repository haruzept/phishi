from celery_app import celery
from check_dns import check_dns
from check_whois import check_domain_age

@celery.task
def dns_check_task(domain):
    return check_dns(domain)

@celery.task
def whois_check_task(domain):
    return check_domain_age(domain)
