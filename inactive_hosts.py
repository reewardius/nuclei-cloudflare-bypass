#!/usr/bin/env python3
import requests
import dns.resolver
import socket
import argparse
from urllib.parse import urlparse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import subprocess
import platform
import asyncio
import aiohttp
import aiodns

# Отключаем предупреждения SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Цвета для вывода
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Список Server заголовков для false positives
FALSE_POSITIVE_SERVERS = [
    'microsoft-azure-application-gateway',
    'lb1',
    'awselb/2.0'
]

def check_dns_fast(domain, timeout=3):
    """Быстрая проверка DNS через socket (самый быстрый метод)"""
    try:
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyname(domain)
        return True, result
    except (socket.gaierror, socket.timeout):
        return False, None
    except Exception as e:
        return False, str(e)

def check_dns_with_dnspython(domain, timeout=3):
    """Проверка через dnspython с исправленным API"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        try:
            answers = resolver.query(domain, 'A')
            if answers:
                return True, [str(rdata) for rdata in answers]
        except AttributeError:
            answers = resolver.resolve(domain, 'A')
            if answers:
                return True, [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
            
        return False, None
    except Exception as e:
        return False, str(e)

def check_dns_parallel(domains, timeout=3, max_workers=20):
    """Параллельная проверка DNS для множества доменов"""
    print(f"{BLUE}[DNS]{RESET} Параллельная проверка {len(domains)} доменов (timeout={timeout}s)...")
    
    results = {}
    
    def check_single_domain(domain):
        success, result = check_dns_fast(domain, timeout)
        if success:
            return domain, True, result
        success, result = check_dns_with_dnspython(domain, timeout)
        return domain, success, result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(check_single_domain, domain): domain 
                          for domain in domains}
        
        for future in as_completed(future_to_domain):
            domain, success, result = future.result()
            results[domain] = {'resolved': success, 'result': result}
            status = f"{GREEN}✓{RESET}" if success else f"{RED}✗{RESET}"
            print(f"  {status} {domain}")
    
    return results

def test_http_fast(url, host_header=None, timeout=5):
    """Быстрый HTTP запрос с следованием за редиректами"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Connection': 'close'
    }
    
    if host_header:
        headers['Host'] = host_header
    
    try:
        response = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=timeout,
            allow_redirects=True,  # Включаем следование за редиректами
            stream=True
        )
        
        body_preview = ""
        try:
            body_preview = response.content[:500].decode('utf-8', errors='ignore')
        except:
            pass
        
        # Проверяем Server заголовок на наличие false positives
        server_header = response.headers.get('Server', '').lower()
        is_false_positive = any(fp.lower() in server_header for fp in FALSE_POSITIVE_SERVERS)
        
        return {
            'success': True,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body_preview': body_preview,
            'error': None,
            'is_false_positive': is_false_positive,
            'final_url': response.url  # Сохраняем финальный URL после редиректов
        }
        
    except Exception as e:
        return {
            'success': False,
            'status_code': None,
            'headers': {},
            'body_preview': "",
            'error': str(e),
            'is_false_positive': False,
            'final_url': url
        }

def test_http_parallel(urls, timeout=5, max_workers=15):
    """Параллельное тестирование HTTP"""
    print(f"{BLUE}[HTTP]{RESET} Параллельное тестирование {len(urls)} URL...")
    
    results = {}
    
    def test_single_url(url_info):
        domain, url = url_info
        for protocol in ['https', 'http']:
            test_url = url.replace('https://', f'{protocol}://').replace('http://', f'{protocol}://')
            result = test_http_fast(test_url, timeout=timeout)
            if result['success'] and is_successful_response(result['status_code']) and not result['is_false_positive']:
                return domain, True, test_url, result
        return domain, False, url, None
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(test_single_url, url_info): url_info[0] 
                          for url_info in urls}
        
        for future in as_completed(future_to_domain):
            domain, success, url, result = future.result()
            results[domain] = {
                'success': success, 
                'url': url, 
                'result': result
            }
            
            if success:
                status_code = result['status_code']
                print(f"  {GREEN}✓{RESET} {domain} -> {status_code}")
            else:
                print(f"  {RED}✗{RESET} {domain}")
    
    return results

def extract_domain(target):
    """Извлекает домен из URL или возвращает как есть"""
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        return parsed.netloc
    return target

def load_targets_from_file(filename):
    """Загружает список целей из файла"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            targets = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        return targets
    except FileNotFoundError:
        print(f"{RED}[ERROR]{RESET} Файл {filename} не найден")
        return []
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Ошибка при чтении файла: {e}")
        return []

def is_successful_response(status_code):
    """Проверяет, является ли ответ успешным (включая 404)"""
    return status_code in [200, 403, 404]

def is_different_response(original_response, host_response):
    """Проверяет, отличается ли ответ с Host заголовком от оригинального"""
    if not original_response['success'] or not host_response['success']:
        return False
    
    # Пропускаем, если любой из ответов - false positive
    if original_response['is_false_positive'] or host_response['is_false_positive']:
        return False
    
    if original_response['status_code'] != host_response['status_code']:
        return True
    
    orig_server = original_response['headers'].get('Server', '').lower()
    host_server = host_response['headers'].get('Server', '').lower()
    if orig_server != host_server:
        return True
    
    orig_content = original_response['headers'].get('Content-Type', '').lower()
    host_content = host_response['headers'].get('Content-Type', '').lower()
    if orig_content != host_content:
        return True
    
    orig_length = original_response['headers'].get('Content-Length', '0')
    host_length = host_response['headers'].get('Content-Length', '0')
    if orig_length != host_length:
        return True
    
    orig_body = original_response['body_preview'][:200]
    host_body = host_response['body_preview'][:200]
    if orig_body != host_body:
        return True
    
    return False

def find_inactive_hosts_fast(targets, dns_timeout=3, http_timeout=5, max_workers=20):
    """Быстрый поиск неактивных хостов"""
    
    print(f"{BLUE}[STEP 1]{RESET} Быстрый анализ {len(targets)} целей...")
    start_time = time.time()
    
    domains = [extract_domain(target) for target in targets]
    dns_results = check_dns_parallel(domains, dns_timeout, max_workers)
    
    http_test_urls = []
    for i, target in enumerate(targets):
        domain = domains[i]
        if dns_results[domain]['resolved']:
            if not target.startswith(('http://', 'https://')):
                url = f'https://{domain}'
            else:
                url = target
            http_test_urls.append((domain, url))
    
    http_results = {}
    if http_test_urls:
        http_results = test_http_parallel(http_test_urls, http_timeout, max_workers)
    
    active_domains = []
    inactive_domains = []
    
    for i, target in enumerate(targets):
        domain = domains[i]
        dns_resolved = dns_results[domain]['resolved']
        
        if dns_resolved and domain in http_results and http_results[domain]['success']:
            active_domains.append({
                'domain': domain,
                'url': http_results[domain]['url'],
                'original': target
            })
        else:
            test_url = f'https://{domain}' if not target.startswith(('http://', 'https://')) else target
            inactive_domains.append({
                'domain': domain,
                'url': test_url,
                'original': target
            })
    
    dns_time = time.time() - start_time
    print(f"\n{CYAN}[РЕЗУЛЬТАТ АНАЛИЗА]{RESET} (время: {dns_time:.2f}s)")
    print(f"  Активных доменов: {len(active_domains)}")
    print(f"  Неактивных доменов: {len(inactive_domains)}")
    
    if not active_domains:
        print(f"{YELLOW}[INFO]{RESET} Нет активных доменов для тестирования")
        return []
    
    if not inactive_domains:
        print(f"{YELLOW}[INFO]{RESET} Нет неактивных доменов для поиска")
        return []
    
    print(f"\n{BLUE}[STEP 2]{RESET} Host Header тестирование...")
    print(f"Тестируем {len(inactive_domains)} неактивных доменов")
    print(f"через {len(active_domains)} активных доменов")
    
    found_access = []
    test_combinations = []
    
    for inactive in inactive_domains:
        for active in active_domains:
            test_combinations.append((inactive, active))
    
    def test_host_header_combination(combination):
        inactive, active = combination
        
        original_response = test_http_fast(active['url'], timeout=http_timeout)
        if not original_response['success'] or original_response['is_false_positive']:
            return None
        
        host_response = test_http_fast(
            active['url'], 
            host_header=inactive['domain'], 
            timeout=http_timeout
        )
        
        if not host_response['success'] or host_response['is_false_positive']:
            return None
            
        if (is_successful_response(host_response['status_code']) and 
            is_different_response(original_response, host_response)):
            
            return {
                'inactive_host': inactive['domain'],
                'inactive_original': inactive['original'],
                'active_host': active['domain'],
                'active_url': host_response['final_url'],  # Используем финальный URL после редиректов
                'active_original': active['original'],
                'status_code': host_response['status_code'],
                'headers': host_response['headers'],
                'body_preview': host_response['body_preview'],
                'original_status': original_response['status_code']
            }
        
        return None
    
    print(f"Параллельное тестирование {len(test_combinations)} комбинаций...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_combination = {executor.submit(test_host_header_combination, combo): combo 
                               for combo in test_combinations}
        
        completed = 0
        for future in as_completed(future_to_combination):
            completed += 1
            if completed % 10 == 0:
                print(f"  Прогресс: {completed}/{len(test_combinations)}")
                
            result = future.result()
            if result:
                found_access.append(result)
                print(f"  {GREEN}[НАЙДЕН ДОСТУП!]{RESET} {result['active_host']} -> {result['inactive_host']} ({result['status_code']})")
    
    total_time = time.time() - start_time
    print(f"\n{CYAN}[ВРЕМЯ ВЫПОЛНЕНИЯ]{RESET} {total_time:.2f} секунды")
    
    return found_access

def print_access_results(found_access):
    """Выводит результаты найденных доступов к неактивным хостам"""
    if not found_access:
        print(f"\n{YELLOW}[NO ACCESS FOUND]{RESET} Доступ к неактивным хостам не найден")
        return
    
    print(f"\n{GREEN}{'='*80}{RESET}")
    print(f"{GREEN}[ACCESS TO INACTIVE HOSTS]{RESET}")
    print(f"{GREEN}{'='*80}{RESET}")
    
    for i, access in enumerate(found_access, 1):
        print(f"\n{GREEN}[ACCESS #{i}]{RESET}")
        print(f"{CYAN}Inactive Host:{RESET} {access['inactive_host']}")
        print(f"{CYAN}Active Host:{RESET} {access['active_host']}")
        print(f"{CYAN}Active URL:{RESET} {access['active_url']}")
        print(f"{CYAN}Status Code:{RESET} {access['status_code']} (original: {access['original_status']})")
        
        interesting_headers = ['server', 'x-powered-by', 'content-type', 'location']
        print(f"{CYAN}Interesting Headers:{RESET}")
        for header_name in interesting_headers:
            if header_name.lower() in [h.lower() for h in access['headers'].keys()]:
                for h_name, h_value in access['headers'].items():
                    if h_name.lower() == header_name.lower():
                        print(f"  {h_name}: {h_value}")
        
        if access['body_preview']:
            print(f"{CYAN}Body Preview:{RESET}")
            print(f"  {access['body_preview'][:200]}...")
        
        print(f"{CYAN}Test Commands:{RESET}")
        print(f"  curl -H \"Host: {access['inactive_host']}\" {access['active_url']} -k -L -I")
        print(f"  nuclei -u {access['active_url']} -H \"Host: {access['inactive_host']}\" -rl 110 -c 25")
        
        print("-" * 60)

def save_results_to_file(found_access, filename):
    """Сохраняет результаты в файл"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("Access to Inactive Hosts Results\n")
            f.write("="*50 + "\n\n")
            
            for i, access in enumerate(found_access, 1):
                f.write(f"Access #{i}\n")
                f.write(f"Try using host header **{access['inactive_host']}** on {access['active_url']}\n")
                f.write(f"Status Code: {access['status_code']}\n")
                f.write(f"Curl Command: curl -H \"Host: {access['inactive_host']}\" {access['active_url']} -k -L -I\n")
                f.write(f"Nuclei Command: nuclei -u {access['active_url']} -H \"Host: {access['inactive_host']}\" -rl 110 -c 25 \n")
                f.write("-" * 50 + "\n\n")
                
        print(f"{GREEN}[SAVED]{RESET} Результаты сохранены в {filename}")
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Ошибка сохранения: {e}")

def main():
    parser = argparse.ArgumentParser(description='Fast Inactive Hosts Finder - быстрый поиск доступа к неактивным хостам')
    parser.add_argument('-f', '--file', required=True, help='Файл со списком доменов/хостов')
    parser.add_argument('--dns-timeout', type=int, default=3, help='Таймаут DNS запросов (по умолчанию: 3)')
    parser.add_argument('--http-timeout', type=int, default=5, help='Таймаут HTTP запросов (по умолчанию: 5)')
    parser.add_argument('-w', '--workers', type=int, default=20, help='Количество потоков (по умолчанию: 20)')
    parser.add_argument('-o', '--output', help='Файл для сохранения результатов')
    
    args = parser.parse_args()
    
    targets = load_targets_from_file(args.file)
    if not targets:
        print(f"{RED}[ERROR]{RESET} Нет целей для тестирования")
        return
    
    print(f"{BLUE}[INFO]{RESET} Загружено {len(targets)} целей")
    print(f"{BLUE}[INFO]{RESET} Быстрый режим: DNS timeout={args.dns_timeout}s, HTTP timeout={args.http_timeout}s, workers={args.workers}")
    
    found_access = find_inactive_hosts_fast(
        targets, 
        args.dns_timeout, 
        args.http_timeout, 
        args.workers
    )
    
    print_access_results(found_access)
    
    if args.output and found_access:
        save_results_to_file(found_access, args.output)
    
    print(f"\n{BLUE}[FINAL STATS]{RESET}")
    print(f"Всего целей: {len(targets)}")
    print(f"Найдено доступов к неактивным хостам: {len(found_access)}")

if __name__ == "__main__":
    main()
