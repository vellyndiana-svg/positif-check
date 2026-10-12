from flask import Flask, render_template, request, jsonify
import requests
import re
import time
import threading
from bs4 import BeautifulSoup
from datetime import datetime
import logging
from typing import List, Tuple, Optional, Dict
import hashlib

app = Flask(__name__)

# ===== RELAY CONFIG =====
RELAY_URL = "https://griffin-eligible-satisfy-provider.trycloudflare.com"
RELAY_ENABLED = True
# ========================

# Configuration
TRUSTPOSITIF_BASE = "https://trustpositif.komdigi.go.id/"
TRUSTPOSITIF_API = "https://trustpositif.komdigi.go.id/Rest_server/getrecordsname_home"
MAX_DOMAINS_PER_REQUEST = 5
BATCH_SIZE = 5
MAX_WORKERS = 2
REQUEST_DELAY = 2.5
MAX_DOMAINS = 2000
CACHE_DURATION = 3600
TOKEN_REFRESH_INTERVAL = 300

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global cache
domain_cache = {}

# Lock untuk cache
cache_lock = threading.Lock()


class TrustPositifChecker:
    def __init__(self):
        self.lock = threading.Lock()
        self.last_request_time = 0
        self.request_count = 0
        self.token = None
        self.session = None
        self.token_timestamp = None

    def get_token(self) -> Optional[str]:
        """Get token with caching and refresh (dipakai hanya untuk mode direct)"""
        current_time = datetime.now()

        with self.lock:
            if (not self.token or not self.token_timestamp or
                    (current_time - self.token_timestamp).seconds > TOKEN_REFRESH_INTERVAL):

                try:
                    if not self.session:
                        self.session = requests.Session()
                        self.session.headers.update({
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                            'Accept': 'application/json, text/javascript, */*; q=0.01',
                            'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
                            'X-Requested-With': 'XMLHttpRequest',
                            'Referer': TRUSTPOSITIF_BASE
                        })

                    resp = self.session.get(TRUSTPOSITIF_BASE, timeout=15)
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    token_input = soup.find('input', {'name': 'csrf_token'})

                    if token_input and 'value' in token_input.attrs:
                        self.token = token_input['value']
                    else:
                        self.token = "c86f7fbfbe0782670fc83918a838fd21"

                    self.token_timestamp = current_time
                    logger.info("Token refreshed successfully")

                except Exception as e:
                    logger.error(f"Failed to get token: {e}")
                    self.token = "c86f7fbfbe0782670fc83918a838fd21"
                    self.token_timestamp = current_time

            return self.token

    def rate_limiter(self):
        """Implement rate limiting"""
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time

            if time_since_last < REQUEST_DELAY:
                time.sleep(REQUEST_DELAY - time_since_last)

            self.last_request_time = time.time()
            self.request_count += 1

    def check_domain_batch(self, domains: List[str], retry_count: int = 2) -> List[Tuple[str, str]]:
        """Check domains via relay (VPN Indonesia)"""
        if not domains:
            return []

        # ===== PAKAI RELAY =====
        if RELAY_ENABLED:
            for attempt in range(retry_count + 1):
                try:
                    self.rate_limiter()
                    logger.info(f"Sending {len(domains)} domains to relay")

                    resp = requests.post(
                        f"{RELAY_URL}/relay/check",
                        json={'domains': domains},
                        timeout=180
                    )

                    if resp.status_code == 200:
                        data = resp.json()
                        results = data.get('results', [])
                        logger.info(f"Relay returned {len(results)} results")
                        return [(d, s) for d, s in results]
                    else:
                        logger.error(f"Relay HTTP {resp.status_code}: {resp.text[:200]}")

                except requests.Timeout:
                    logger.warning(f"Relay timeout attempt {attempt + 1}")
                    if attempt < retry_count:
                        time.sleep(3)
                        continue
                except Exception as e:
                    logger.error(f"Relay error: {e}")
                    if attempt < retry_count:
                        time.sleep(3)
                        continue

            return [(domain, "RELAY_ERROR") for domain in domains]

        # ===== Fallback: direct ke TrustPositif (kalau relay dimatikan) =====
        token = self.get_token()

        for attempt in range(retry_count + 1):
            try:
                self.rate_limiter()

                payload = {
                    'csrf_token': token,
                    'name': "\n".join(domains)
                }

                if self.session:
                    resp = self.session.post(TRUSTPOSITIF_API, data=payload, timeout=20)
                else:
                    resp = requests.post(TRUSTPOSITIF_API, data=payload, timeout=20)

                content_type = resp.headers.get('Content-Type', '')

                if 'application/json' in content_type or resp.text.strip().startswith('{'):
                    data = resp.json()

                    if isinstance(data, list):
                        results = []
                        for item in data:
                            domain = item.get('Domain', '')
                            status = item.get('Status', 'Tidak Diketahui')
                            results.append((domain, status))
                        return results

                    elif 'values' in data and isinstance(data['values'], list):
                        results = []
                        for i, item in enumerate(data['values']):
                            domain = item.get('Domain', domains[i] if i < len(domains) else '')
                            status = item.get('Status', 'Tidak Ada')

                            if status.lower() in ['ada', 'blocked', 'terblokir', 'true', '1', 'yes']:
                                status = "Ada"
                            elif status.lower() in ['tidak ada', 'aman', 'not found', 'false', '0', 'no']:
                                status = "Tidak Ada"

                            results.append((domain, status))
                        return results

                    else:
                        logger.warning("API response structure not recognized, trying scraping...")
                        return self.check_via_scraping(domains)

                else:
                    logger.warning("Non-JSON response for batch, trying scraping...")
                    return self.check_via_scraping(domains)

            except requests.Timeout:
                logger.warning("Timeout for batch")
                if attempt < retry_count:
                    time.sleep(3)
                    continue
                else:
                    return [(domain, "TIMEOUT") for domain in domains]

            except Exception as e:
                logger.error(f"Error checking batch: {e}")
                if attempt < retry_count:
                    time.sleep(3)
                    continue
                else:
                    return [(domain, "ERROR") for domain in domains]

        return [(domain, "ERROR") for domain in domains]

    def check_via_scraping(self, domains: List[str]) -> List[Tuple[str, str]]:
        """Fallback method: Scrape TrustPositif website directly"""
        results = []
        try:
            if not self.session:
                self.session = requests.Session()
                self.session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Referer': TRUSTPOSITIF_BASE
                })

            home_resp = self.session.get(TRUSTPOSITIF_BASE, timeout=15)
            soup = BeautifulSoup(home_resp.text, 'html.parser')
            token_input = soup.find('input', {'name': 'csrf_token'})
            token = token_input['value'] if token_input else self.token

            for domain in domains:
                search_url = f"{TRUSTPOSITIF_BASE}?domain={domain}"
                resp = self.session.get(search_url, timeout=15)

                if resp.status_code == 200:
                    result_soup = BeautifulSoup(resp.text, 'html.parser')
                    status_text = "Tidak Ada"
                    page_text = result_soup.get_text()

                    if "Tidak Ada" in page_text:
                        status_text = "Tidak Ada"
                    elif "Ada" in page_text:
                        status_text = "Ada"
                    else:
                        status_text = "Tidak Diketahui"

                    results.append((domain, status_text))
                else:
                    results.append((domain, "ERROR"))

                time.sleep(REQUEST_DELAY)

        except Exception as e:
            logger.error(f"Scraping failed: {e}")
            results = [(domain, "ERROR") for domain in domains]

        return results

    def process_domains_batch(self, domains: List[str], progress_callback=None) -> Dict[str, str]:
        """Process large number of domains with accurate progress tracking"""
        results = {}
        total_domains = len(domains)

        # Pisahkan domain yang sudah ada di cache dan yang belum
        domains_to_check = []
        for domain in domains:
            cached = self.get_from_cache(domain)
            if cached:
                results[domain] = cached
            else:
                domains_to_check.append(domain)

        # Kalau semua sudah ada di cache, langsung selesai
        if not domains_to_check:
            if progress_callback:
                progress_callback(1, 1, len(results), total_domains)
            return results

        # Progress awal: domain yang sudah ada di cache
        if progress_callback:
            progress_callback(0, 1, len(results), total_domains)

        total_batches = (len(domains_to_check) + BATCH_SIZE - 1) // BATCH_SIZE
        processed_count = len(results)  # mulai dari yang sudah di cache

        for batch_idx in range(0, len(domains_to_check), BATCH_SIZE):
            batch = domains_to_check[batch_idx:batch_idx + BATCH_SIZE]

            sub_batches = [batch[i:i + MAX_DOMAINS_PER_REQUEST]
                           for i in range(0, len(batch), MAX_DOMAINS_PER_REQUEST)]

            for sub_batch in sub_batches:
                batch_results = self.check_domain_batch(sub_batch)

                for domain, status in batch_results:
                    results[domain] = status
                    self.save_to_cache(domain, status)
                    processed_count += 1

            # Update progress SETELAH setiap batch selesai, dengan hitungan akurat
            if progress_callback:
                current_batch = batch_idx // BATCH_SIZE + 1
                progress_callback(current_batch, total_batches, processed_count, total_domains)

            if batch_idx + BATCH_SIZE < len(domains_to_check):
                time.sleep(1)

        return results

    def get_from_cache(self, domain: str) -> Optional[str]:
        with cache_lock:
            if domain in domain_cache:
                cached_data = domain_cache[domain]
                if (datetime.now() - cached_data['timestamp']).seconds < CACHE_DURATION:
                    return cached_data['status']
        return None

    def save_to_cache(self, domain: str, status: str):
        with cache_lock:
            domain_cache[domain] = {
                'status': status,
                'timestamp': datetime.now()
            }

            if len(domain_cache) > 10000:
                sorted_items = sorted(domain_cache.items(),
                                      key=lambda x: x[1]['timestamp'])
                for old_domain, _ in sorted_items[:1000]:
                    del domain_cache[old_domain]


# Initialize checker
checker = TrustPositifChecker()

# Global progress tracking dengan lock untuk thread-safety
progress_lock = threading.Lock()
progress_data = {
    'total': 0,
    'completed': 0,
    'results': {},
    'status': 'idle',
    'start_time': None,
    'end_time': None,
    'task_id': None
}


def process_large_domain_list(task_id: str, domains: List[str]):
    """Process domain list di background thread dengan progress tracking yang akurat"""
    global progress_data

    with progress_lock:
        progress_data.update({
            'total': len(domains),
            'completed': 0,
            'results': {},
            'status': 'processing',
            'start_time': datetime.now(),
            'end_time': None,
            'task_id': task_id
        })

    def update_progress(batch_num, total_batches, result_count, total_domains):
        """Update progress berdasarkan jumlah domain yang sudah selesai diproses"""
        with progress_lock:
            completed = min(result_count, total_domains)
            progress_data['completed'] = completed

    try:
        results = checker.process_domains_batch(domains, update_progress)

        with progress_lock:
            progress_data.update({
                'completed': len(domains),
                'results': results,
                'status': 'completed',
                'end_time': datetime.now()
            })
    except Exception as e:
        logger.error(f"Error in background processing: {e}")
        with progress_lock:
            progress_data.update({
                'status': 'error',
                'end_time': datetime.now()
            })


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check_domains():
    """Check domains"""
    try:
        data = request.get_json(silent=True)
        if not data or 'domains' not in data:
            return jsonify({'error': 'Data tidak valid!'}), 400

        domains_raw = data.get('domains', [])

        domains = []
        seen = set()

        for line in domains_raw:
            line = line.strip().lower()
            if not line:
                continue

            line = re.sub(r'^https?://', '', line)
            line = line.rstrip('/')
            line = line.split('/')[0]

            if re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$', line):
                if line not in seen:
                    domains.append(line)
                    seen.add(line)

        if not domains:
            return jsonify({'error': 'Tidak ada domain valid untuk dicek!'}), 400

        if len(domains) > MAX_DOMAINS:
            return jsonify({
                'error': f'Maksimal {MAX_DOMAINS} domain per permintaan!',
                'max_domains': MAX_DOMAINS
            }), 400

        if len(domains) > 100:
            task_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]

            thread = threading.Thread(
                target=process_large_domain_list,
                args=(task_id, domains),
                daemon=True
            )
            thread.start()

            return jsonify({
                'status': 'processing',
                'task_id': task_id,
                'total_domains': len(domains),
                'message': f'Processing {len(domains)} domains in background'
            })

        start_time = time.time()
        results = checker.process_domains_batch(domains)
        processing_time = time.time() - start_time

        ordered_results = [(domain, results.get(domain, "TIDAK DIKETAHUI")) for domain in domains]

        return jsonify({
            'results': ordered_results,
            'total_domains': len(domains),
            'processing_time': f'{processing_time:.2f} seconds',
            'status': 'completed'
        })

    except Exception as e:
        logger.error(f"Error in check_domains: {e}")
        return jsonify({'error': f'Terjadi kesalahan: {str(e)}'}), 500


@app.route('/progress/<task_id>')
def get_progress(task_id):
    """Get progress of background processing dengan perhitungan yang selalu akurat"""
    global progress_data

    with progress_lock:
        if progress_data.get('task_id') != task_id:
            return jsonify({'error': 'Task tidak ditemukan!'}), 404

        status = progress_data.get('status')
        total = progress_data.get('total', 0)
        completed = progress_data.get('completed', 0)

        # Selalu hitung percentage, jangan bergantung pada kondisi tertentu
        if total > 0:
            progress_percentage = (completed / total) * 100
        else:
            progress_percentage = 0

        # Pastikan percentage tidak melebihi 100
        progress_percentage = min(progress_percentage, 100.0)

        response_data = {
            'task_id': task_id,
            'status': status,
            'total_domains': total,
            'completed_domains': completed,
            'progress_percentage': round(progress_percentage, 2)
        }

        if status == 'completed':
            results = progress_data.get('results', {})
            ordered_results = []
            for domain, status_val in results.items():
                ordered_results.append((domain, status_val))

            response_data['results'] = ordered_results

            start_time = progress_data.get('start_time')
            end_time = progress_data.get('end_time')
            if start_time and end_time:
                response_data['processing_time'] = str(end_time - start_time)
            else:
                response_data['processing_time'] = '0:00:00'

        elif status == 'error':
            response_data['error'] = 'Terjadi kesalahan saat memproses domain'

    return jsonify(response_data)


@app.route('/stats')
def get_stats():
    """Get checker statistics"""
    with cache_lock:
        cache_size = len(domain_cache)

    return jsonify({
        'cache_size': cache_size,
        'total_requests': checker.request_count,
        'token_age_seconds': (datetime.now() - checker.token_timestamp).seconds if checker.token_timestamp else None,
        'relay_enabled': RELAY_ENABLED,
        'relay_url': RELAY_URL
    })


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port, threaded=True)
