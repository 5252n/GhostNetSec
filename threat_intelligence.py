import requests
from datetime import datetime, timedelta
from .app import app
import sqlite3

class ThreatIntelligence:
    def __init__(self):
        self.api_keys = {
            'virustotal': app.config.get('VIRUSTOTAL_API_KEY'),
            'abuseipdb': app.config.get('ABUSEIPDB_API_KEY'),
            'shodan': app.config.get('SHODAN_API_KEY')
        }
        self.cache = {}
    
    def check_ip_reputation(self, ip_address):
        """Check IP reputation against multiple threat intelligence feeds"""
        if ip_address in self.cache:
            if self.cache[ip_address]['expires'] > datetime.utcnow():
                return self.cache[ip_address]['data']
        
        results = {
            'virustotal': self._check_virustotal(ip_address),
            'abuseipdb': self._check_abuseipdb(ip_address),
            'shodan': self._check_shodan(ip_address)
        }
        
        # Store in cache for 1 hour
        self.cache[ip_address] = {
            'data': results,
            'expires': datetime.utcnow() + timedelta(hours=1)
        }
        
        return results
    
    def _check_virustotal(self, ip_address):
        """Check IP with VirusTotal"""
        if not self.api_keys['virustotal']:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'malicious': data['data']['attributes']['last_analysis_stats']['malicious'],
                    'suspicious': data['data']['attributes']['last_analysis_stats']['suspicious'],
                    'reputation': data['data']['attributes']['reputation']
                }
            else:
                return {'error': f"API error: {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_abuseipdb(self, ip_address):
        """Check IP with AbuseIPDB"""
        if not self.api_keys['abuseipdb']:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'Key': self.api_keys['abuseipdb']}
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'
            }
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'abuse_confidence': data['data']['abuseConfidenceScore'],
                    'isp': data['data']['isp'],
                    'usage_type': data['data']['usageType']
                }
            else:
                return {'error': f"API error: {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}
    
    def _check_shodan(self, ip_address):
        """Check IP with Shodan"""
        if not self.api_keys['shodan']:
            return {'error': 'API key not configured'}
        
        try:
            response = requests.get(
                f'https://api.shodan.io/shodan/host/{ip_address}?key={self.api_keys["shodan"]}'
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'ports': data.get('ports', []),
                    'vulnerabilities': data.get('vulns', []),
                    'tags': data.get('tags', [])
                }
            else:
                return {'error': f"API error: {response.status_code}"}
        except Exception as e:
            return {'error': str(e)}
    
    def update_device_threat_level(self, device_id):
        """Update device threat level based on threat intelligence"""
        db = sqlite3.connect(app.config['DATABASE'])
        cursor = db.cursor()
        
        # Get device IP
        cursor.execute("SELECT ip FROM devices WHERE id = ?", (device_id,))
        device = cursor.fetchone()
        
        if not device:
            return False
        
        ip_address = device[0]
        ti_data = self.check_ip_reputation(ip_address)
        
        # Calculate threat level (0-10)
        threat_level = 0
        
        # VirusTotal scoring
        vt_data = ti_data.get('virustotal', {})
        if 'malicious' in vt_data:
            threat_level += vt_data['malicious'] * 2  # Each malicious report adds 2 points
        if 'suspicious' in vt_data:
            threat_level += vt_data['suspicious']    # Each suspicious report adds 1 point
        if vt_data.get('reputation', 0) < 0:
            threat_level += abs(vt_data['reputation']) // 10  # Negative reputation adds points
        
        # AbuseIPDB scoring
        abuse_data = ti_data.get('abuseipdb', {})
        if 'abuse_confidence' in abuse_data:
            threat_level += abuse_data['abuse_confidence'] // 10  # 0-100 scale to 0-10
        
        # Shodan scoring
        shodan_data = ti_data.get('shodan', {})
        if 'vulnerabilities' in shodan_data:
            threat_level += len(shodan_data['vulnerabilities']) * 2  # Each vulnerability adds 2 points
        
        # Cap at 10
        threat_level = min(10, threat_level)
        
        # Update database
        cursor.execute(
            "UPDATE devices SET threat_level = ? WHERE id = ?",
            (threat_level, device_id)
        )
        db.commit()
        db.close()
        
        return True