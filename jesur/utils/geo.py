"""
JESUR - Enhanced SMB Share Scanner
Geolocation module - IP range lookup by country code

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import ipaddress
import requests
from jesur.utils.cache import cache_manager

def get_country_ip_ranges(country_code):
    """Get IP ranges for a specific country using RIPEstat API"""
    
    # Load cache
    geo_cache = cache_manager.load_geo_ip_cache()
    
    # Check cache first
    if country_code in geo_cache:
        print(f"[*] Loading {country_code} IP ranges from cache...")
        networks = []
        for net_str in geo_cache[country_code]:
            try:
                networks.append(ipaddress.IPv4Network(net_str))
            except ValueError:
                continue
        return networks
    
    print(f"[*] Fetching IP ranges for {country_code}...")
    networks = []
    
    try:
        # RIPE API endpoint
        url = f"https://stat.ripe.net/data/country-resource-list/data.json?resource={country_code}"
        response = requests.get(url, timeout=30)
        data = response.json()
        
        if data['status'] == 'ok':
            # Get IPv4 ranges
            cached_networks = []
            for ip_range in data['data']['resources']['ipv4']:
                try:
                    # Convert to CIDR network
                    if '/' not in ip_range:
                        ip_range = f"{ip_range}/32"
                    network = ipaddress.IPv4Network(ip_range)
                    networks.append(network)
                    cached_networks.append(str(network))
                except ValueError:
                    continue
            
            # Cache the results
            geo_cache[country_code] = cached_networks
            cache_manager.save_geo_ip_cache(geo_cache)
            
            print(f"[+] Found {len(networks)} networks for {country_code}")
            return networks
    except Exception as e:
        print(f"[-] Error fetching IP ranges: {str(e)}")
    
    return networks

def list_country_codes():
    """List all available country codes"""
    country_codes = {
        'af_AF': 'Afghanistan',
        'al_AL': 'Albania',
        'dz_DZ': 'Algeria',
        'ad_AD': 'Andorra',
        'ao_AO': 'Angola',
        'ag_AG': 'Antigua and Barbuda',
        'ar_AR': 'Argentina',
        'am_AM': 'Armenia',
        'au_AU': 'Australia',
        'at_AT': 'Austria',
        'az_AZ': 'Azerbaijan',
        'bs_BS': 'Bahamas',
        'bh_BH': 'Bahrain',
        'bd_BD': 'Bangladesh',
        'bb_BB': 'Barbados',
        'by_BY': 'Belarus',
        'be_BE': 'Belgium',
        'bz_BZ': 'Belize',
        'bj_BJ': 'Benin',
        'bt_BT': 'Bhutan',
        'bo_BO': 'Bolivia',
        'ba_BA': 'Bosnia and Herzegovina',
        'bw_BW': 'Botswana',
        'br_BR': 'Brazil',
        'bn_BN': 'Brunei',
        'bg_BG': 'Bulgaria',
        'bf_BF': 'Burkina Faso',
        'bi_BI': 'Burundi',
        'kh_KH': 'Cambodia',
        # ... (Shortened list for brevity, original list is huge)
        'tr_TR': 'Turkey',
        'us_US': 'United States',
        'uk_GB': 'United Kingdom',
        'de_DE': 'Germany'
    }
    
    print("\nAvailable Country Codes (Top Used):")
    print("-" * 50)
    print(f"{'Code':<10} {'Country':<30}")
    print("-" * 50)
    for code, country in sorted(country_codes.items()):
        print(f"{code:<10} {country:<30}")
    print("\n(Note: This is a truncated list for display. All standard codes are supported.)")
