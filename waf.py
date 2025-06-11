#!/usr/bin/env python3
import requests
import re
import sys
import argparse
from urllib.parse import urlparse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def check_cloudflare(headers, body=""):
    """Проверяет наличие индикаторов Cloudflare"""
    cf_indicators = [
        'cloudflare', 'cf-ray', 'cf-cache-status', 'cf-request-id', 
        '__cflb', '__cfuid', 'cf-cache-control'
    ]
    
    # Проверяем заголовки
    for key, value in headers.items():
        key_lower = key.lower()
        value_lower = str(value).lower()
        
        # Проверяем ключи и значения заголовков
        if any(indicator in key_lower for indicator in cf_indicators):
            return True
        if any(indicator in value_lower for indicator in cf_indicators):
            return True
        
        # Специальная проверка для Server заголовка
        if key_lower == 'server' and 'cloudflare' in value_lower:
            return True
    
    # Проверяем тело ответа
    body_lower = body.lower() if body else ""
    if any(indicator in body_lower for indicator in ['cloudflare', 'ray id']):
        return True
        
    return False

def test_single_request(url, host_header=None, timeout=10):
    """Выполняет один HTTP запрос"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    if host_header:
        headers['Host'] = host_header
    
    try:
        response = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=timeout,
            allow_redirects=False
        )
        
        body_preview = response.text[:300] if response.text else ""
        
        return {
            'success': True,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body_preview': body_preview,
            'is_cloudflare': check_cloudflare(response.headers, body_preview),
            'error': None
        }
        
    except Exception as e:
        return {
            'success': False,
            'status_code': None,
            'headers': {},
            'body_preview': "",
            'is_cloudflare': False,
            'error': str(e)
        }

def extract_domain(target):
    """Извлекает домен из цели"""
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'
    
    parsed = urlparse(target)
    return parsed.netloc

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
    """Проверяет, является ли статус код успешным для bypass"""
    # Успешные коды: 2xx, 3xx (редиректы), некоторые 4xx могут быть валидными
    return status_code in range(200, 400) or status_code in [401, 403, 405]

def analyze_targets(targets, timeout=10):
    """Анализирует все цели и ищет обходы WAF"""
    
    # Шаг 1: Найти цели за Cloudflare
    print(f"{BLUE}[STEP 1]{RESET} Поиск целей за Cloudflare WAF...")
    cloudflare_targets = []
    non_cloudflare_targets = []
    
    for i, target in enumerate(targets, 1):
        if not target.startswith(('http://', 'https://')):
            target_url = f'https://{target}'
        else:
            target_url = target
            
        print(f"  [{i}/{len(targets)}] Проверяем {target}")
        
        result = test_single_request(target_url, timeout=timeout)
        
        if not result['success']:
            print(f"    {RED}✗{RESET} Ошибка: {result['error']}")
            continue
            
        if result['is_cloudflare']:
            print(f"    {GREEN}✓{RESET} За Cloudflare (статус: {result['status_code']})")
            cloudflare_targets.append({
                'original': target,
                'url': target_url,
                'domain': extract_domain(target)
            })
        else:
            print(f"    {YELLOW}○{RESET} Не за Cloudflare (статус: {result['status_code']})")
            non_cloudflare_targets.append({
                'original': target,
                'url': target_url,
                'domain': extract_domain(target)
            })
    
    print(f"\n{CYAN}[РЕЗУЛЬТАТ СКАНИРОВАНИЯ]{RESET}")
    print(f"  Целей за Cloudflare: {len(cloudflare_targets)}")
    print(f"  Целей не за Cloudflare: {len(non_cloudflare_targets)}")
    
    if not cloudflare_targets:
        print(f"{YELLOW}[INFO]{RESET} Нет целей за Cloudflare для тестирования обхода")
        return []
    
    if not non_cloudflare_targets:
        print(f"{YELLOW}[INFO]{RESET} Нет целей для использования в качестве обходного пути")
        return []
    
    # Шаг 2: Тестировать обходы
    print(f"\n{BLUE}[STEP 2]{RESET} Тестирование обходов WAF...")
    print(f"Будем обращаться к {len(non_cloudflare_targets)} целям НЕ за Cloudflare")
    print(f"используя {len(cloudflare_targets)} целей ЗА Cloudflare как Host заголовки")
    
    bypasses_found = []
    
    for non_cf_target in non_cloudflare_targets:
        print(f"\n{MAGENTA}[TESTING]{RESET} {non_cf_target['original']}")
        
        for cf_target in cloudflare_targets:
            cf_domain = cf_target['domain']
            
            # Тестируем с Host заголовком от цели за Cloudflare
            result = test_single_request(
                non_cf_target['url'], 
                host_header=cf_domain, 
                timeout=timeout
            )
            
            if not result['success']:
                print(f"  {RED}✗{RESET} Host: {cf_domain} -> ошибка: {result['error']}")
                continue
            
            # ИСПРАВЛЕННАЯ ЛОГИКА: 
            # Bypass найден, если:
            # 1. Получили успешный ответ
            # 2. НЕТ заголовков Cloudflare (значит обошли WAF)
            if is_successful_response(result['status_code']) and not result['is_cloudflare']:
                bypass_info = {
                    'base_url': non_cf_target['url'],
                    'base_original': non_cf_target['original'],
                    'host_header': cf_domain,
                    'host_original': cf_target['original'],
                    'status_code': result['status_code'],
                    'headers': result['headers'],
                    'body_preview': result['body_preview']
                }
                
                bypasses_found.append(bypass_info)
                
                print(f"  {GREEN}[BYPASS FOUND!]{RESET} Host: {cf_domain} -> статус: {result['status_code']} (без Cloudflare!)")
            elif result['is_cloudflare']:
                print(f"  {YELLOW}○{RESET} Host: {cf_domain} -> статус: {result['status_code']} (за Cloudflare)")
            else:
                print(f"  {RED}○{RESET} Host: {cf_domain} -> статус: {result['status_code']} (неуспешный)")
    
    return bypasses_found

def print_bypass_results(bypasses):
    """Выводит детальные результаты найденных обходов"""
    if not bypasses:
        print(f"\n{YELLOW}[NO BYPASSES]{RESET} Обходы WAF не найдены")
        return
    
    print(f"\n{GREEN}{'='*80}{RESET}")
    print(f"{GREEN}[WAF BYPASS RESULTS]{RESET}")
    print(f"{GREEN}{'='*80}{RESET}")
    
    for i, bypass in enumerate(bypasses, 1):
        print(f"\n{GREEN}[BYPASS #{i}]{RESET}")
        print(f"{CYAN}Base URL:{RESET} {bypass['base_url']}")
        print(f"{CYAN}Host Header:{RESET} {bypass['host_header']}")
        print(f"{CYAN}Status Code:{RESET} {bypass['status_code']}")
        
        # Показываем интересные заголовки
        interesting_headers = ['server', 'x-powered-by', 'x-real-ip', 'x-forwarded-for', 'location']
        print(f"{CYAN}Interesting Headers:{RESET}")
        for header_name in interesting_headers:
            if header_name.lower() in [h.lower() for h in bypass['headers'].keys()]:
                for h_name, h_value in bypass['headers'].items():
                    if h_name.lower() == header_name.lower():
                        print(f"  {h_name}: {h_value}")
        
        # Показываем превью тела ответа
        if bypass['body_preview']:
            print(f"{CYAN}Body Preview:{RESET}")
            print(f"  {bypass['body_preview'][:200]}...")
        
        # Показываем curl команду для воспроизведения
        print(f"{CYAN}Curl Command:{RESET}")
        print(f"  curl -H 'Host: {bypass['host_header']}' '{bypass['base_url']}' -k")
        
        print("-" * 60)

def save_results_to_file(bypasses, filename):
    """Сохраняет результаты в файл"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("WAF Bypass Results\n")
            f.write("="*50 + "\n\n")
            
            for i, bypass in enumerate(bypasses, 1):
                f.write(f"Bypass #{i}\n")
                f.write(f"Base URL: {bypass['base_url']}\n")
                f.write(f"Host Header: {bypass['host_header']}\n")
                f.write(f"Status Code: {bypass['status_code']}\n")
                f.write(f"Curl Command: curl -H 'Host: {bypass['host_header']}' '{bypass['base_url']}' -k\n")
                f.write("-" * 50 + "\n\n")
                
        print(f"{GREEN}[SAVED]{RESET} Результаты сохранены в {filename}")
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Ошибка сохранения: {e}")

def main():
    parser = argparse.ArgumentParser(description='WAF Bypass Hunter - поиск обходов Cloudflare через Host Header')
    parser.add_argument('-f', '--file', required=True, help='Файл со списком целей')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Таймаут запросов (по умолчанию: 10)')
    parser.add_argument('-o', '--output', help='Файл для сохранения результатов')
    
    args = parser.parse_args()
    
    # Загружаем цели
    targets = load_targets_from_file(args.file)
    if not targets:
        print(f"{RED}[ERROR]{RESET} Нет целей для тестирования")
        return
    
    print(f"{BLUE}[INFO]{RESET} Загружено {len(targets)} целей")
    print(f"{BLUE}[INFO]{RESET} Начинаем поиск обходов Cloudflare WAF...")
    
    # Анализируем цели
    bypasses = analyze_targets(targets, args.timeout)
    
    # Выводим результаты
    print_bypass_results(bypasses)
    
    # Сохраняем результаты
    if args.output and bypasses:
        save_results_to_file(bypasses, args.output)
    
    # Итоговая статистика
    print(f"\n{BLUE}[FINAL STATS]{RESET}")
    print(f"Всего целей: {len(targets)}")
    print(f"Найдено обходов: {len(bypasses)}")

if __name__ == "__main__":
    main()