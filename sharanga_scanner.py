import os
import socket
import platform
import psutil
import wmi
import winreg
import subprocess
import json
from datetime import datetime, timedelta
import sys
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import hashlib
import time
from dotenv import load_dotenv

load_dotenv()

class SharangaScanner:
    def __init__(self):
        self.device_info = {}
        self.system_config = {}
        self.alert_config = {
            'email': {
                'sender': os.getenv('SMTP_EMAIL', ''),
                'password': os.getenv('SMTP_PASSWORD', ''),
                'recipient': os.getenv('ALERT_EMAIL', 'security@company.com')
            },
            'telegram': {
                'bot_token': os.getenv('TELEGRAM_BOT_TOKEN', ''),
                'chat_id': os.getenv('TELEGRAM_CHAT_ID', '')
            },
            'slack': {
                'webhook_url': os.getenv('SLACK_WEBHOOK_URL', '')
            },
            'vt_api_key': os.getenv('VIRUSTOTAL_API_KEY', '')
        }
        
        try:
            self.c = wmi.WMI()
        except:
            self.c = None

    # ============================================================
    # EMAIL/TELEGRAM/SLACK ALERTS
    # ============================================================
    def send_email_alert(self, subject, body, is_html=False):
        try:
            sender = self.alert_config['email']['sender']
            password = self.alert_config['email']['password']
            recipient = self.alert_config['email']['recipient']
            
            if not sender or not password:
                return False
            
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = recipient
            msg['Subject'] = f"🏹 Sharanga Alert - {subject}"
            
            if is_html:
                msg.attach(MIMEText(body, 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            server.quit()
            return True
        except:
            return False

    def send_telegram_alert(self, message):
        try:
            bot_token = self.alert_config['telegram']['bot_token']
            chat_id = self.alert_config['telegram']['chat_id']
            if not bot_token or not chat_id:
                return False
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {'chat_id': chat_id, 'text': f"🏹 Sharanga Alert\n\n{message}"}
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200
        except:
            return False

    def send_slack_alert(self, message):
        try:
            webhook_url = self.alert_config['slack']['webhook_url']
            if not webhook_url:
                return False
            
            payload = {'text': f"🏹 Sharanga Alert\n\n{message}", 'mrkdwn': True}
            response = requests.post(webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except:
            return False

    def send_alerts(self, device_name, risk_score, suspicious_processes):
        if risk_score < 50 and not suspicious_processes:
            return
        
        message = f"""
🚨 HIGH RISK DETECTED

📍 Device: {device_name}
📊 Risk Score: {risk_score}/100
⚠️ Suspicious Processes: {len(suspicious_processes)}

Suspicious Processes:
{chr(10).join([f"  🔴 {p['name']} (PID: {p['pid']})" for p in suspicious_processes[:5]])}

⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        self.send_email_alert(f"🚨 HIGH RISK on {device_name}", message)
        self.send_telegram_alert(message)
        self.send_slack_alert(message)

    # ============================================================
    # GET WEATHER
    # ============================================================
    def get_weather(self, city=None):
        weather_info = {
            'city': 'Unknown',
            'temperature': '--°C',
            'feels_like': '--°C',
            'condition': 'Unknown',
            'humidity': '--%',
            'wind_speed': '-- km/h',
            'pressure': '-- hPa',
            'visibility': '-- km',
            'sunrise': '--:--',
            'sunset': '--:--',
            'icon': '🌤️'
        }
        
        try:
            if not city:
                try:
                    ip_response = requests.get('https://ipapi.co/json/', timeout=10)
                    if ip_response.status_code == 200:
                        ip_data = ip_response.json()
                        city = ip_data.get('city', '')
                        region = ip_data.get('region', '')
                        country = ip_data.get('country_name', '')
                        if city:
                            weather_info['city'] = f"{city}, {region}, {country}"
                        elif region:
                            weather_info['city'] = f"{region}, {country}"
                except:
                    pass
            
            if not city or city == 'Unknown':
                city = 'Delhi'
            
            url = f"https://wttr.in/{city}?format=j1"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                current = data.get('current_condition', [{}])[0]
                
                temp_c = current.get('temp_C', '--')
                weather_info['temperature'] = f"{temp_c}°C"
                
                feels = current.get('FeelsLikeC', '--')
                weather_info['feels_like'] = f"{feels}°C"
                
                condition = current.get('weatherDesc', [{}])[0].get('value', 'Unknown')
                weather_info['condition'] = condition
                
                humidity = current.get('humidity', '--')
                weather_info['humidity'] = f"{humidity}%"
                
                wind = current.get('windspeedKmph', '--')
                weather_info['wind_speed'] = f"{wind} km/h"
                
                pressure = current.get('pressure', '--')
                weather_info['pressure'] = f"{pressure} hPa"
                
                visibility = current.get('visibility', '--')
                weather_info['visibility'] = f"{visibility} km"
                
                weather_code = current.get('weatherCode', '0')
                weather_info['icon'] = self.get_weather_icon(weather_code)
                
                astronomy = data.get('weather', [{}])[0].get('astronomy', [{}])[0] if data.get('weather') else {}
                weather_info['sunrise'] = astronomy.get('sunrise', '--:--')
                weather_info['sunset'] = astronomy.get('sunset', '--:--')
                
                area_name = data.get('nearest_area', [{}])[0].get('areaName', [{}])[0].get('value', '')
                region_name = data.get('nearest_area', [{}])[0].get('region', [{}])[0].get('value', '')
                country_name = data.get('nearest_area', [{}])[0].get('country', [{}])[0].get('value', '')
                
                if area_name:
                    weather_info['city'] = f"{area_name}, {region_name}, {country_name}"
                elif region_name:
                    weather_info['city'] = f"{region_name}, {country_name}"
        except Exception as e:
            weather_info['condition'] = 'Weather API Error'
            weather_info['error'] = str(e)
        
        return weather_info

    def get_weather_icon(self, code):
        icons = {
            '113': '☀️', '116': '⛅', '119': '☁️', '122': '☁️', '143': '🌫️',
            '176': '🌦️', '179': '🌨️', '182': '🌧️', '185': '🌧️', '200': '⛈️',
            '227': '🌨️', '230': '🌨️', '248': '🌫️', '260': '🌫️', '263': '🌦️',
            '266': '🌦️', '281': '🌧️', '284': '🌧️', '293': '🌦️', '296': '🌦️',
            '299': '🌧️', '302': '🌧️', '305': '🌧️', '308': '🌧️', '311': '🌨️',
            '314': '🌨️', '317': '🌨️', '320': '🌨️', '323': '🌨️', '326': '🌨️',
            '329': '🌨️', '332': '🌨️', '335': '❄️', '338': '❄️', '350': '🌧️',
            '353': '🌦️', '356': '🌧️', '359': '🌧️', '362': '🌨️', '365': '🌨️',
            '368': '🌨️', '371': '🌨️', '374': '🌧️', '377': '🌧️', '386': '⛈️',
            '389': '⛈️', '392': '⛈️', '395': '⛈️'
        }
        return icons.get(code, '🌤️')

    # ============================================================
    # GET DEVICE INFO
    # ============================================================
    def get_device_info(self):
        try:
            system = self.c.Win32_ComputerSystem()[0]
            
            self.device_info['device_name'] = system.Name
            self.device_info['username'] = system.UserName
            self.device_info['domain'] = system.Domain
            self.device_info['os_name'] = platform.system()
            self.device_info['os_version'] = platform.version()
            self.device_info['os_release'] = platform.release()
            self.device_info['processor'] = platform.processor() or 'Unknown'
            self.device_info['ram_gb'] = round(int(system.TotalPhysicalMemory) / (1024**3), 2)
            
            try:
                hostname = socket.gethostname()
                self.device_info['ip_address'] = socket.gethostbyname(hostname)
            except:
                self.device_info['ip_address'] = 'Unknown'
            
            self.device_info['is_domain_joined'] = system.Domain != 'WORKGROUP'
            
            # System Manufacturer + Model
            if system.Manufacturer:
                self.device_info['system_manufacturer'] = system.Manufacturer
            else:
                try:
                    reg_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    self.device_info['system_manufacturer'] = winreg.QueryValueEx(key, "SystemManufacturer")[0]
                except:
                    self.device_info['system_manufacturer'] = 'Unknown'
            
            if system.Model:
                self.device_info['system_model'] = system.Model
            else:
                try:
                    reg_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    self.device_info['system_model'] = winreg.QueryValueEx(key, "SystemProductName")[0]
                except:
                    self.device_info['system_model'] = 'Unknown'
            
        except Exception as e:
            self.device_info['device_name'] = os.environ.get('COMPUTERNAME', 'Unknown')
            self.device_info['username'] = os.environ.get('USERNAME', 'Unknown')
            self.device_info['domain'] = os.environ.get('USERDOMAIN', 'WORKGROUP')
            self.device_info['os_name'] = platform.system()
            self.device_info['os_version'] = platform.version()
            self.device_info['os_release'] = platform.release()
            self.device_info['processor'] = platform.processor() or 'Unknown'
            self.device_info['ram_gb'] = round(psutil.virtual_memory().total / (1024**3), 2)
            self.device_info['ip_address'] = socket.gethostbyname(socket.gethostname())
            self.device_info['is_domain_joined'] = self.device_info['domain'] != 'WORKGROUP'
            self.device_info['system_manufacturer'] = 'Unknown'
            self.device_info['system_model'] = 'Unknown'
        
        return self.device_info

    # ============================================================
    # GET SYSTEM CONFIG - BALARC LEVEL (IMPORTANT ONLY)
    # ============================================================
    def get_system_config(self):
        config = {}
        
        try:
            # Uptime & Boot Time
            config['uptime'] = self.get_uptime()
            config['boot_time'] = datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
            
            # Battery
            try:
                battery = psutil.sensors_battery()
                if battery:
                    config['battery_percent'] = battery.percent
                    config['battery_status'] = 'Charging' if battery.power_plugged else 'Discharging'
            except:
                pass
            
            # Weather
            print("🌤️ Fetching weather data...")
            weather = self.get_weather()
            config['weather'] = weather
            
            # Disk Drives
            disks = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disks.append({
                        'drive': partition.device,
                        'total_gb': round(usage.total / (1024**3), 2),
                        'used_gb': round(usage.used / (1024**3), 2),
                        'free_gb': round(usage.free / (1024**3), 2),
                        'used_percent': usage.percent
                    })
                except:
                    pass
            config['disks'] = disks
            
            # ========== CPU - Important Only ==========
            cpu_info = {}
            if self.c:
                for cpu in self.c.Win32_Processor():
                    cpu_info['name'] = cpu.Name or 'Unknown'
                    cpu_info['cores'] = cpu.NumberOfCores or 'Unknown'
                    cpu_info['logical'] = cpu.NumberOfLogicalProcessors or 'Unknown'
                    cpu_info['max_clock'] = f"{cpu.MaxClockSpeed} MHz" if cpu.MaxClockSpeed else 'Unknown'
                    cpu_info['current_clock'] = f"{cpu.CurrentClockSpeed} MHz" if cpu.CurrentClockSpeed else 'Unknown'
                    cpu_info['usage'] = psutil.cpu_percent(interval=1)
                    break
            else:
                cpu_info['name'] = platform.processor() or 'Unknown'
                cpu_info['cores'] = psutil.cpu_count(logical=False) or 'Unknown'
                cpu_info['logical'] = psutil.cpu_count(logical=True) or 'Unknown'
                cpu_info['max_clock'] = 'Unknown'
                cpu_info['current_clock'] = 'Unknown'
                cpu_info['usage'] = psutil.cpu_percent(interval=1)
            config['cpu'] = cpu_info
            
            # ========== Memory ==========
            mem = psutil.virtual_memory()
            config['memory'] = {
                'total_gb': round(mem.total / (1024**3), 2),
                'used_gb': round(mem.used / (1024**3), 2),
                'available_gb': round(mem.available / (1024**3), 2),
                'used_percent': mem.percent
            }
            
            # ========== Motherboard ==========
            motherboard_info = {'name': 'Unknown', 'manufacturer': 'Unknown'}
            try:
                if self.c:
                    for board in self.c.Win32_BaseBoard():
                        if board.Product:
                            motherboard_info['name'] = board.Product
                        if board.Manufacturer:
                            motherboard_info['manufacturer'] = board.Manufacturer
                        break
            except:
                pass
            
            if motherboard_info['name'] == 'Unknown':
                try:
                    reg_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    try:
                        motherboard_info['name'] = winreg.QueryValueEx(key, "SystemProductName")[0]
                    except:
                        pass
                    try:
                        motherboard_info['manufacturer'] = winreg.QueryValueEx(key, "SystemManufacturer")[0]
                    except:
                        pass
                except:
                    pass
            
            config['motherboard'] = motherboard_info
            
            # ========== BIOS ==========
            bios_info = {'version': 'Unknown', 'manufacturer': 'Unknown'}
            try:
                if self.c:
                    for bios in self.c.Win32_BIOS():
                        if bios.SMBIOSBIOSVersion:
                            bios_info['version'] = bios.SMBIOSBIOSVersion
                        if bios.Manufacturer:
                            bios_info['manufacturer'] = bios.Manufacturer
                        break
            except:
                pass
            
            if bios_info['version'] == 'Unknown':
                try:
                    reg_path = r"SYSTEM\CurrentControlSet\Control\SystemInformation"
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    try:
                        bios_info['version'] = winreg.QueryValueEx(key, "BIOSVersion")[0]
                    except:
                        pass
                except:
                    pass
            
            config['bios'] = bios_info
            
            # ========== GPU ==========
            gpus = []
            if self.c:
                for gpu in self.c.Win32_VideoController():
                    if gpu.Name and 'Microsoft' not in gpu.Name:
                        gpu_ram = 'Unknown'
                        try:
                            if gpu.AdapterRAM:
                                gpu_ram = f"{gpu.AdapterRAM / (1024**3):.2f} GB"
                        except:
                            pass
                        gpus.append({
                            'name': gpu.Name,
                            'ram': gpu_ram,
                            'driver': gpu.DriverVersion or 'Unknown'
                        })
            if not gpus:
                gpus.append({'name': 'Integrated Graphics', 'ram': 'Unknown', 'driver': 'Unknown'})
            config['gpus'] = gpus
            
        except Exception as e:
            config['error'] = str(e)
        
        return config

    def get_uptime(self):
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{days}d {hours}h {minutes}m"

    # ============================================================
    # GET NETWORK INFO
    # ============================================================
    def get_network_info(self):
        network_info = {
            'connection_type': 'Unknown',
            'ip_address': 'Unknown',
            'mac_address': 'Unknown',
            'ssid': 'Unknown',
            'speed': 'Unknown',
            'interface': 'Unknown',
            'gateway': 'Unknown',
            'dhcp_server': 'Unknown'
        }
        
        try:
            if self.c:
                for adapter in self.c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    if adapter.IPAddress:
                        for ip in adapter.IPAddress:
                            if ip != '127.0.0.1' and ':' not in ip:
                                network_info['ip_address'] = ip
                                
                                if adapter.Description:
                                    network_info['interface'] = adapter.Description
                                
                                if adapter.MACAddress:
                                    network_info['mac_address'] = adapter.MACAddress
                                
                                if adapter.DefaultIPGateway:
                                    network_info['gateway'] = adapter.DefaultIPGateway[0]
                                
                                if adapter.DHCPServer:
                                    network_info['dhcp_server'] = adapter.DHCPServer
                                
                                desc = adapter.Description.lower() if adapter.Description else ''
                                
                                wifi_keywords = ['wi-fi', 'wlan', 'wireless', '802.11', 'wifi']
                                if any(kw in desc for kw in wifi_keywords):
                                    network_info['connection_type'] = 'Wi-Fi'
                                    try:
                                        result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                                              capture_output=True, text=True)
                                        for line in result.stdout.split('\n'):
                                            line = line.strip()
                                            if 'SSID' in line and ':' in line:
                                                ssid = line.split(':', 1)[1].strip()
                                                if ssid and ssid != '':
                                                    network_info['ssid'] = ssid
                                            if 'Speed' in line and ':' in line:
                                                speed_val = line.split(':', 1)[1].strip()
                                                if speed_val:
                                                    network_info['speed'] = speed_val
                                    except:
                                        pass
                                elif 'ethernet' in desc or 'gigabit' in desc or 'realtek' in desc or 'intel' in desc:
                                    network_info['connection_type'] = 'Ethernet'
                                    try:
                                        for net_adapter in self.c.Win32_NetworkAdapter():
                                            if net_adapter.Description and net_adapter.Description.lower() == desc:
                                                if net_adapter.Speed:
                                                    speed_val = int(net_adapter.Speed)
                                                    if speed_val >= 1000000000:
                                                        network_info['speed'] = f"{speed_val // 1000000000} Gbps"
                                                    elif speed_val >= 1000000:
                                                        network_info['speed'] = f"{speed_val // 1000000} Mbps"
                                                    else:
                                                        network_info['speed'] = f"{speed_val} bps"
                                                break
                                    except:
                                        pass
                                break
        except Exception as e:
            network_info['error'] = str(e)
        
        # Fallback for Wi-Fi
        if network_info['connection_type'] == 'Unknown':
            try:
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
                if 'SSID' in result.stdout and 'BSSID' in result.stdout:
                    network_info['connection_type'] = 'Wi-Fi'
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if 'SSID' in line and ':' in line:
                            ssid = line.split(':', 1)[1].strip()
                            if ssid and ssid != '':
                                network_info['ssid'] = ssid
                else:
                    network_info['connection_type'] = 'Ethernet'
            except:
                network_info['connection_type'] = 'Ethernet'
        
        # Fallback for MAC
        if network_info['mac_address'] == 'Unknown':
            try:
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Physical Address' in line:
                        mac = line.split(':', 1)[1].strip()
                        if mac and mac != '' and '--' not in mac:
                            network_info['mac_address'] = mac
                            break
            except:
                pass
        
        # Fallback for Interface
        if network_info['interface'] == 'Unknown':
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'adapter' in line.lower():
                        interface = line.replace('adapter', '').replace(':', '').strip()
                        if interface and interface != '':
                            network_info['interface'] = interface
                            break
            except:
                pass
        
        # Fallback for Gateway
        if network_info['gateway'] == 'Unknown':
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Default Gateway' in line:
                        gateway = line.split(':', 1)[1].strip()
                        if gateway and gateway != '':
                            network_info['gateway'] = gateway
                            break
            except:
                pass
        
        if network_info['ip_address'] == 'Unknown':
            try:
                hostname = socket.gethostname()
                network_info['ip_address'] = socket.gethostbyname(hostname)
            except:
                pass
        
        return network_info

    # ============================================================
    # GET INSTALLED APPS
    # ============================================================
    def get_installed_apps(self):
        apps = []
        
        registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        for path in registry_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            app_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            if app_name:
                                app_version = 'Unknown'
                                try:
                                    app_version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                except:
                                    pass
                                apps.append({
                                    'name': app_name,
                                    'version': app_version,
                                    'publisher': 'Unknown'
                                })
                        except:
                            pass
                        i += 1
                    except WindowsError:
                        break
            except:
                pass
        
        unique_apps = []
        seen = set()
        for app in apps:
            if app['name'] not in seen:
                unique_apps.append(app)
                seen.add(app['name'])
        
        return unique_apps

    # ============================================================
    # GET UNINSTALLED APPS
    # ============================================================
    def get_uninstalled_apps(self):
        uninstalled = []
        try:
            import win32evtlog
            hand = win32evtlog.OpenEventLog(None, 'Application')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            count = 0
            for event in events:
                if count > 200:
                    break
                if event.EventID in [1034, 11724]:
                    event_time = event.TimeGenerated
                    if event_time:
                        event_time = datetime.fromtimestamp(event_time.timestamp())
                        if (datetime.now() - event_time).days <= 7:
                            app_name = 'Unknown'
                            if event.StringInserts:
                                app_name = event.StringInserts[0]
                            uninstalled.append({
                                'app_name': app_name,
                                'uninstall_date': event_time,
                                'event_id': event.EventID
                            })
                count += 1
            win32evtlog.CloseEventLog(hand)
        except:
            pass
        return uninstalled

    # ============================================================
    # GET RUNNING PROCESSES
    # ============================================================
    def get_running_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'create_time']):
            try:
                proc_info = proc.info
                is_script = False
                script_type = 'Unknown'
                if proc_info['exe']:
                    exe_name = proc_info['exe'].lower()
                    if 'python' in exe_name:
                        is_script = True
                        script_type = 'Python'
                    elif 'powershell' in exe_name:
                        is_script = True
                        script_type = 'PowerShell'
                    elif 'cmd' in exe_name or 'batch' in exe_name:
                        is_script = True
                        script_type = 'Batch'
                is_suspicious = False
                if proc_info['exe']:
                    exe = proc_info['exe'].lower()
                    suspicious_paths = ['\\temp\\', '\\downloads\\', '\\appdata\\local\\temp\\', '\\tmp\\']
                    for path in suspicious_paths:
                        if path in exe:
                            is_suspicious = True
                            break
                processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'exe_path': proc_info['exe'],
                    'command_line': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                    'is_script': is_script,
                    'script_type': script_type if is_script else 'None',
                    'is_suspicious': is_suspicious,
                    'create_time': datetime.fromtimestamp(proc_info['create_time']) if proc_info['create_time'] else None
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return processes

    # ============================================================
    # MAIN SCAN
    # ============================================================
    def scan_system(self):
        print("🔍 Sharanga - Scanning your system...")
        print("=" * 50)
        
        device_info = self.get_device_info()
        system_config = self.get_system_config()
        network_info = self.get_network_info()
        installed_apps = self.get_installed_apps()
        uninstalled_apps = self.get_uninstalled_apps()
        running_processes = self.get_running_processes()
        
        suspicious = [p for p in running_processes if p['is_suspicious']]
        risk_score = min(len(suspicious) * 20, 100)
        
        if risk_score >= 50 or len(suspicious) > 0:
            print(f"🚨 High risk detected! Risk Score: {risk_score}")
            self.send_alerts(
                device_name=device_info.get('device_name', 'Unknown'),
                risk_score=risk_score,
                suspicious_processes=suspicious
            )
        
        full_report = {
            'scan_time': datetime.now().isoformat(),
            'device': device_info,
            'system_config': system_config,
            'network': network_info,
            'installed_apps': installed_apps,
            'uninstalled_apps': uninstalled_apps,
            'running_processes': running_processes,
            'stats': {
                'total_apps': len(installed_apps),
                'total_uninstalled': len(uninstalled_apps),
                'total_processes': len(running_processes),
                'suspicious_processes': len(suspicious),
                'risk_score': risk_score
            }
        }
        return full_report

    def display_report(self, report):
        print("\n" + "=" * 60)
        print("🏹 SHARANGA - SYSTEM SCAN REPORT")
        print("=" * 60)
        
        device = report['device']
        config = report['system_config']
        network = report['network']
        stats = report['stats']
        weather = config.get('weather', {})
        cpu = config.get('cpu', {})
        memory = config.get('memory', {})
        motherboard = config.get('motherboard', {})
        bios = config.get('bios', {})
        gpus = config.get('gpus', [])
        
        print("\n📱 DEVICE INFORMATION")
        print("-" * 40)
        print(f"  Device Name         : {device['device_name']}")
        print(f"  User Name           : {device['username']}")
        print(f"  Domain              : {device['domain']}")
        print(f"  Domain Joined       : {'✅ Yes' if device['is_domain_joined'] else '❌ No'}")
        print(f"  OS                  : {device['os_name']} {device['os_release']}")
        print(f"  IP Address          : {device['ip_address']}")
        print(f"  RAM                 : {device['ram_gb']} GB")
        print(f"  System Manufacturer : {device.get('system_manufacturer', 'Unknown')}")
        print(f"  System Model        : {device.get('system_model', 'Unknown')}")
        
        print("\n⚙️ CPU")
        print("-" * 40)
        print(f"  Name           : {cpu.get('name', 'Unknown')}")
        print(f"  Cores          : {cpu.get('cores', 'Unknown')} Physical | {cpu.get('logical', 'Unknown')} Logical")
        print(f"  Max Clock      : {cpu.get('max_clock', 'Unknown')}")
        print(f"  Current Clock  : {cpu.get('current_clock', 'Unknown')}")
        print(f"  Usage          : {cpu.get('usage', 0)}%")
        
        print("\n💾 MEMORY")
        print("-" * 40)
        print(f"  Total          : {memory.get('total_gb', 0)} GB")
        print(f"  Used           : {memory.get('used_gb', 0)} GB ({memory.get('used_percent', 0)}%)")
        print(f"  Available      : {memory.get('available_gb', 0)} GB")
        
        print("\n🖥️  MOTHERBOARD")
        print("-" * 40)
        print(f"  Name           : {motherboard.get('name', 'Unknown')}")
        print(f"  Manufacturer   : {motherboard.get('manufacturer', 'Unknown')}")
        
        print("\n🔧 BIOS")
        print("-" * 40)
        print(f"  Version        : {bios.get('version', 'Unknown')}")
        print(f"  Manufacturer   : {bios.get('manufacturer', 'Unknown')}")
        
        if gpus:
            print("\n🎮 GRAPHICS")
            print("-" * 40)
            for gpu in gpus:
                print(f"  Name           : {gpu.get('name', 'Unknown')}")
                print(f"  VRAM           : {gpu.get('ram', 'Unknown')}")
                print(f"  Driver         : {gpu.get('driver', 'Unknown')}")
        
        print("\n🌐 NETWORK")
        print("-" * 40)
        conn_type = network.get('connection_type', 'Unknown')
        icon = "📶" if conn_type == 'Wi-Fi' else "🔌" if conn_type == 'Ethernet' else "❓"
        print(f"  {icon} Connection Type: {conn_type}")
        print(f"  Interface      : {network.get('interface', 'Unknown')}")
        print(f"  MAC Address    : {network.get('mac_address', 'Unknown')}")
        print(f"  IP Address     : {network.get('ip_address', 'Unknown')}")
        if conn_type == 'Wi-Fi':
            print(f"  SSID           : {network.get('ssid', 'Unknown')}")
        else:
            print(f"  Speed          : {network.get('speed', 'Unknown')}")
        print(f"  Gateway        : {network.get('gateway', 'Unknown')}")
        
        print("\n🌤️ WEATHER")
        print("-" * 40)
        print(f"  {weather.get('icon', '🌤️')} {weather.get('city', 'Unknown')}")
        print(f"  Temperature    : {weather.get('temperature', '--°C')}")
        print(f"  Condition      : {weather.get('condition', 'Unknown')}")
        print(f"  Humidity       : {weather.get('humidity', '--%')}")
        print(f"  Wind Speed     : {weather.get('wind_speed', '-- km/h')}")
        
        print("\n💾 DISK DRIVES")
        print("-" * 40)
        for disk in config.get('disks', []):
            print(f"  {disk['drive']} - {disk['total_gb']} GB ({disk['used_percent']}% used)")
        
        print("\n📊 SUMMARY")
        print("-" * 40)
        print(f"  Total Applications  : {stats['total_apps']}")
        print(f"  Running Processes   : {stats['total_processes']}")
        print(f"  Suspicious Processes: {stats['suspicious_processes']}")
        print(f"  Uninstalled (7 days): {stats['total_uninstalled']}")
        
        risk_score = stats.get('risk_score', 0)
        risk_level = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH"
        print(f"\n  🎯 RISK SCORE: {risk_score}/100 ({risk_level})")
        
        print("\n" + "=" * 60)
        print("🏹 Sharanga - Scan Complete!")
        print("=" * 60)
    
    def save_report_json(self, report, filename="sharanga_report.json"):
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n✅ Report saved as {filename}")

if __name__ == "__main__":
    scanner = SharangaScanner()
    report = scanner.scan_system()
    scanner.display_report(report)
    scanner.save_report_json(report)