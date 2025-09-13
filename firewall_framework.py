#!/usr/bin/env python3

import paramiko
import yaml
import logging
import re
import time
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from netaddr import IPNetwork, IPSet, AddrFormatError, IPAddress
from collections import defaultdict


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_framework.log', mode='w'),
        logging.StreamHandler()
    ]
)
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


class FirewallFramework:
    def __init__(self, config_path: str = 'config.yaml'):
        self.config = self.load_config(config_path)
        self.connectors = {
            'cisco_asa': CiscoASAConnector,
            'fortios': FortiOSConnector,
            'paloalto': PaloAltoConnector
        }
        self.parsers = {
            'cisco_asa': CiscoASAParser,
            'fortios': FortiOSParser,
            'paloalto': PaloAltoParser
        }
        self.firewall_data = {}
        self.anomalies = {}
        self.resolutions = []
        self.resolution_engine = AdvancedResolutionEngine()
        self.deployment_engine = DeploymentEngine(self.config['firewalls'], self.connectors)

    def load_config(self, config_path: str) -> Dict:
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config file {config_path}: {e}")
            raise

    def connect_to_firewalls(self) -> bool:
        logger.info("Connecting to firewalls and extracting configurations...")
        for fw_config in self.config['firewalls']:
            fw_type = fw_config.get('type')
            fw_name = fw_config.get('name')
            if fw_type not in self.connectors:
                logger.error(f"Unsupported firewall type: {fw_type} for {fw_name}")
                continue
            try:
                connector = self.connectors[fw_type](fw_config)
                raw_config = connector.get_config()
                if not raw_config:
                    logger.warning(f"No configuration retrieved from {fw_name}")
                    continue

                parser = self.parsers[fw_type]()
                parsed_data = parser.parse(raw_config)
                self.firewall_data[fw_name] = {
                    'name': fw_name,
                    'type': fw_type,
                    **parsed_data
                }
                logger.info(f"Successfully processed {fw_name} ({len(parsed_data.get('rules', []))} rules parsed).")
            except Exception as e:
                logger.error(f"Failed to process {fw_name}: {e}", exc_info=True)
        return len(self.firewall_data) > 0

    def detect_anomalies(self) -> bool:
        logger.info("Detecting anomalies...")
        anomaly_engine = AnomalyEngine(self.firewall_data, self.config.get('zone_mappings', {}))
        
        for fw_name in self.firewall_data:
            self.anomalies[fw_name] = anomaly_engine.analyze_intra_firewall(fw_name)
        
        self.anomalies['inter_firewall'] = anomaly_engine.analyze_inter_firewall()
        return True

    def generate_resolutions(self) -> bool:
        logger.info("Generating resolution tasks...")
        self.resolutions = self.resolution_engine.generate_all_resolutions(self.anomalies)
        return True

    def deploy_changes(self, mode='dry_run'):
        logger.info(f"Preparing to deploy changes in '{mode}' mode...")
        self.deployment_engine.deploy(self.resolutions, mode=mode)
    
    def output_results(self):
        print("\n" + "="*80 + "\nFIREWALL ANOMALY DETECTION FRAMEWORK - RESULTS\n" + "="*80)
        total_anomalies = sum(len(v) for v in self.anomalies.values())
        print(f"\nANOMALIES DETECTED ({total_anomalies}):")
        if total_anomalies == 0:
            print("  No anomalies detected.")
        else:
            for scope, anomalies in self.anomalies.items():
                if anomalies:
                    print(f"\n--- {scope.upper()} ---")
                    for anom in sorted(anomalies, key=lambda x: x['type']):
                        print(f"  - TYPE: {anom['type'].upper()}\n    DESC: {anom['description']}\n")

        print(f"\nRESOLUTION TASKS GENERATED ({len(self.resolutions)}):")
        if not self.resolutions:
            print("  No resolution tasks generated.")
        else:
            for task in self.resolutions:
                print(f"\n--- TASK FOR: {task['firewall_name']} ---")
                print(f"  DESC: {task['description']}")
                print(f"  COMMANDS:")
                for cmd in task['commands']:
                    print(f"    {cmd}")
        
        with open('framework_results.json', 'w') as f:
            json.dump({'anomalies': self.anomalies, 'resolutions': self.resolutions}, f, indent=2, default=str)
        logger.info("Detailed results saved to framework_results.json")

    def run(self):
        logger.info("Starting framework execution")
        if self.connect_to_firewalls() and self.detect_anomalies() and self.generate_resolutions():
            self.output_results()
            
            if self.resolutions:
                choice = input("\nDo you want to apply these changes? (Type 'enforce' to apply, anything else to cancel): ")
                if choice.lower() == 'enforce':
                    self.deploy_changes(mode='enforce')
                else:
                    print("\nDeployment cancelled. No changes were made.")

            logger.info("Framework execution completed successfully.")
        else:
            logger.error("Framework execution failed.")

class BaseConnector:
    def __init__(self, config: Dict):
        self.config = config
        self.ssh = None
        self.timeout = 30

    def connect(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(
            hostname=self.config['ip'], 
            username=self.config['username'],
            password=self.config['password'], 
            timeout=self.timeout,
            look_for_keys=False, 
            allow_agent=False
        )
        logger.info(f"Connected to {self.config['name']}")

    def disconnect(self):
        if self.ssh:
            self.ssh.close()

    def _wait_for_prompt(self, shell, prompt_pattern):
        output = ""
        end_time = time.time() + self.timeout
        while time.time() < end_time:
            if shell.recv_ready():
                output += shell.recv(65535).decode(errors='ignore')
                if re.search(prompt_pattern, output):
                    return output
            time.sleep(0.2)
        raise TimeoutError("Timed out waiting for prompt")

    def send_command(self, shell, command, prompt_pattern=r'[\w\s.-]+[>#]\s*$'):
        shell.sendall(command + '\n')
        return self._wait_for_prompt(shell, prompt_pattern)

    def get_full_config(self, term_len_cmd, show_cmd):
        try:
            self.connect()
            shell = self.ssh.invoke_shell()
            time.sleep(1)
            self.send_command(shell, term_len_cmd)
            config = self.send_command(shell, show_cmd)
            shell.close()
            return config
        finally:
            self.disconnect()

class CiscoASAConnector(BaseConnector):
    def get_config(self):
        enable_pass = self.config.get('enable_password', '')
        try:
            self.connect()
            shell = self.ssh.invoke_shell()
            time.sleep(2)
            self._wait_for_prompt(shell, r'>\s*$')
            logger.info(f"Sending 'enable' command to {self.config['name']}")
            shell.sendall('enable\n')
            self._wait_for_prompt(shell, r'Password:\s*')
            logger.info(f"Sending enable password to {self.config['name']}")
            shell.sendall(f'{enable_pass}\n')
            self._wait_for_prompt(shell, r'#\s*$')
            logger.info(f"Successfully entered enable mode on {self.config['name']}")
            self.send_command(shell, "terminal pager 0")
            config = self.send_command(shell, "show running-config")
            shell.close()
            return config
        finally:
            self.disconnect()

class PaloAltoConnector(BaseConnector):
    def get_config(self):
        return self.get_full_config("set cli pager off", "show config running")

class FortiOSConnector(BaseConnector):
    def get_config(self):
        try:
            self.connect()
            shell = self.ssh.invoke_shell()
            time.sleep(1)
            self.send_command(shell, "config system console")
            self.send_command(shell, "set output standard")
            self.send_command(shell, "end")
            config = self.send_command(shell, "show full-configuration")
            shell.close()
            return config
        finally:
            self.disconnect()

class BaseParser:
    def parse(self, config_text: str) -> Dict:
        return {'rules': [], 'addr_objects': {}, 'svc_objects': {}}

class CiscoASAParser(BaseParser):
    def parse(self, config_text: str) -> Dict:
        data = super().parse(config_text)
        for match in re.finditer(r'object network (\S+)\n(.*?)(?=object network|\Z)', config_text, re.DOTALL):
            name, content = match.groups()
            host_match = re.search(r'host (\S+)', content)
            subnet_match = re.search(r'subnet (\S+) (\S+)', content)
            range_match = re.search(r'range (\S+) (\S+)', content)
            if host_match: data['addr_objects'][name] = host_match.group(1)
            elif subnet_match:
                mask = subnet_match.group(2)
                cidr = IPAddress(mask).netmask_bits()
                data['addr_objects'][name] = f"{subnet_match.group(1)}/{cidr}"
            elif range_match: data['addr_objects'][name] = f"{range_match.group(1)}-{range_match.group(2)}"
        
        for match in re.finditer(r'object service (\S+)\n(.*?)(?=object service|\Z)', config_text, re.DOTALL):
            name, content = match.groups()
            service_match = re.search(r'service (tcp|udp) destination eq (\S+)', content)
            if service_match:
                proto, port = service_match.groups()
                data['svc_objects'][name] = {'protocol': proto, 'port': port}
        
        for line in config_text.splitlines():
            line = line.strip()
            if not line.startswith('access-list'): continue
            parts = line.split()
            if len(parts) < 6 or parts[2] != 'extended': continue
            try:
                rule = {'name': parts[1], 'action': parts[3], 'protocol': parts[4], 'source': 'any', 'destination': 'any', 'service': 'any', 'raw_line': line}
                idx = 5
                idx, rule['source'] = self._parse_addr_component(parts, idx)
                idx, rule['destination'] = self._parse_addr_component(parts, idx)
                if idx < len(parts) and parts[idx] in ['eq', 'object-group']:
                    idx += 1
                    if idx < len(parts): rule['service'] = parts[idx]
                data['rules'].append(rule)
            except IndexError:
                logger.warning(f"Could not parse complex ASA rule: {line}")
        return data

    def _parse_addr_component(self, parts: list, start_idx: int) -> Tuple[int, str]:
        keyword = parts[start_idx] if start_idx < len(parts) else ""
        if keyword == 'any': return start_idx + 1, 'any'
        if keyword == 'host': return start_idx + 2, parts[start_idx + 1]
        if keyword == 'object-group': return start_idx + 2, parts[start_idx + 1]
        if '.' in keyword and start_idx + 1 < len(parts) and '.' in parts[start_idx + 1]:
             ip, mask = parts[start_idx], parts[start_idx + 1]
             cidr = IPAddress(mask).netmask_bits()
             return start_idx + 2, f"{ip}/{cidr}"
        return start_idx + 1, keyword

class PaloAltoParser(BaseParser):
    def parse(self, config_text: str) -> Dict:
        data = super().parse(config_text)
        addr_pattern = re.compile(r'set address "([^"]+)" (ip-netmask|ip-range|fqdn) "([^"]+)"')
        for name, _, value in addr_pattern.findall(config_text):
            data['addr_objects'][name] = value
        
        svc_pattern = re.compile(r'set service "([^"]+)" protocol (tcp|udp) port ([0-9-]+)')
        for name, proto, port in svc_pattern.findall(config_text):
            data['svc_objects'][name] = {'protocol': proto, 'port': port}
        
        rules_dict = defaultdict(dict)
        rule_pattern = re.compile(r'set rulebase security rules "([^"]+)" (\S+) (.*)')
        for name, param, value in rule_pattern.findall(config_text):
            value = value.strip()
            if value.startswith('[') and value.endswith(']'):
                rules_dict[name][param] = re.findall(r'"([^"]+)"', value)
            else:
                rules_dict[name][param] = value.strip('"')
        
        for name, props in rules_dict.items():
            data['rules'].append({
                'name': name, 'action': props.get('action', 'allow'), 'from_zone': props.get('from', ['any']),
                'to_zone': props.get('to', ['any']), 'source': props.get('source', ['any']),
                'destination': props.get('destination', ['any']), 'service': props.get('service', ['any']),
                'raw_line': f"Rule '{name}'"
            })
        return data

class FortiOSParser(BaseParser):
    def _parse_forti_list(self, line: str) -> List[str]:
        return re.findall(r'"([^"]+)"', line)

    def parse(self, config_text: str) -> Dict:
        data = super().parse(config_text)
        
        addr_section = re.search(r'config firewall address\n(.*?)\nend', config_text, re.DOTALL)
        if addr_section:
            for name, content in re.findall(r'edit "([^"]+)"\n(.*?)(?=\nedit|\nend)', addr_section.group(1), re.DOTALL):
                if 'set subnet' in content:
                    ip, mask = re.search(r'set subnet (\S+) (\S+)', content).groups()
                    data['addr_objects'][name] = f"{ip}/{IPAddress(mask).netmask_bits()}"
        
        svc_section = re.search(r'config firewall service custom\n(.*?)\nend', config_text, re.DOTALL)
        if svc_section:
            for name, content in re.findall(r'edit "([^"]+)"\n(.*?)(?=\nedit|\nend)', svc_section.group(1), re.DOTALL):
                match = re.search(r'set (tcp|udp)-portrange ([0-9-]+)', content)
                if match: data['svc_objects'][name] = {'protocol': match.group(1), 'port': match.group(2)}
        
        policy_section = re.search(r'config firewall policy\n(.*?)\nend', config_text, re.DOTALL)
        if policy_section:
            for policy_id, content in re.findall(r'edit (\d+)\n(.*?)(?=\nedit|\nend)', policy_section.group(1), re.DOTALL):
                props = {}
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith('set '):
                        _, key, value = line.split(maxsplit=2)
                        props[key] = self._parse_forti_list(line) if '"' in value else value
                
                data['rules'].append({
                    'name': props.get('name', f"policy-{policy_id}").strip('"'),
                    'action': props.get('action', 'deny'), 'srcintf': props.get('srcintf', ['any']),
                    'dstintf': props.get('dstintf', ['any']), 'srcaddr': props.get('srcaddr', ['any']),
                    'dstaddr': props.get('dstaddr', ['any']), 'service': props.get('service', ['any']),
                    'raw_line': f"Policy ID {policy_id}"
                })
        return data

class AnomalyEngine:
    def __init__(self, firewall_data: Dict, zone_mappings: Dict):
        self.firewall_data = firewall_data
        self.zone_map = {}
        for canon_zone, fw_zones in zone_mappings.items():
            for fw_zone in fw_zones:
                self.zone_map[fw_zone] = canon_zone

    def _resolve_address(self, name: Any, fw_name: str) -> IPSet:
        if isinstance(name, list):
            final_set = IPSet()
            for item in name:
                final_set.update(self._resolve_address(item, fw_name))
            return final_set

        if not isinstance(name, str): name = str(name)
        if name.lower() in ['any', 'all']: return IPSet(['0.0.0.0/0'])
        
        try: return IPSet([IPNetwork(name)])
        except (AddrFormatError, ValueError): pass
        
        addr_objects = self.firewall_data[fw_name].get('addr_objects', {})
        if name in addr_objects:
            return self._resolve_address(addr_objects[name], fw_name)
        
        return IPSet()

    def _resolve_service(self, name: Any, fw_name: str) -> Set[Tuple[str, int, int]]:
        if isinstance(name, list):
            final_set = set()
            for item in name:
                final_set.update(self._resolve_service(item, fw_name))
            return final_set

        if not isinstance(name, str): name = str(name)
        name = name.lower()
        if name in ['any', 'all']: return {('tcp', 1, 65535), ('udp', 1, 65535)}
        
        svc_objects = self.firewall_data[fw_name].get('svc_objects', {})
        if name in svc_objects:
            svc = svc_objects[name]
            protocol = svc.get('protocol', 'tcp').lower()
            port_str = str(svc.get('port', '1-65535'))
            if '-' in port_str: p_start, p_end = map(int, port_str.split('-'))
            else: p_start = p_end = int(port_str)
            return {(protocol, p_start, p_end)}
        
        return set()

    def _services_overlap(self, svc1: Set, svc2: Set) -> bool:
        for p1, s1, e1 in svc1:
            for p2, s2, e2 in svc2:
                if p1 == p2 and not (e1 < s2 or e2 < s1):
                    return True
        return False

    def _get_canonical_zone(self, rule: Dict, fw_name: str, direction: str) -> str:
        keys = {'source': ['from_zone', 'srcintf'], 'destination': ['to_zone', 'dstintf']}
        for key in keys[direction]:
            if key in rule:
                val_list = rule[key]
                val = val_list[0] if isinstance(val_list, list) and val_list else val_list
                return self.zone_map.get(f"{fw_name}:{val}", str(val))
        return 'any'

    def analyze_intra_firewall(self, fw_name: str) -> List[Dict]:
        anomalies = []
        rules = self.firewall_data[fw_name].get('rules', [])
        for i, rule in enumerate(rules):
            rule['id'] = rule.get('name', f"rule-{i+1}")
        
        for rule in rules:
            src_names = rule.get('source', ['any'])
            dst_names = rule.get('destination', ['any'])
            svc_names = rule.get('service', ['any'])
            if 'any' in (src_names if isinstance(src_names, list) else [src_names]) and \
               'any' in (dst_names if isinstance(dst_names, list) else [dst_names]) and \
               'any' in (svc_names if isinstance(svc_names, list) else [svc_names]):
                anomalies.append({'type': 'generalization', 'description': f"Rule '{rule['id']}' on {fw_name} is overly general (any/any/any)."})

        for i, r1 in enumerate(rules):
            for r2 in rules[i + 1:]:
                src1, dst1, svc1 = self._resolve_address(r1.get('source'), fw_name), self._resolve_address(r1.get('destination'), fw_name), self._resolve_service(r1.get('service'), fw_name)
                src2, dst2, svc2 = self._resolve_address(r2.get('source'), fw_name), self._resolve_address(r2.get('destination'), fw_name), self._resolve_service(r2.get('service'), fw_name)
                
                if not all([src1, dst1, svc1, src2, dst2, svc2]): continue
                
                is_subset = (src2.issubset(src1) and dst2.issubset(dst1) and self._services_overlap(svc2, svc1))
                if not is_subset: continue
                
                if r1.get('action') == r2.get('action'):
                    anomalies.append({
                        'type': 'redundancy', 'description': f"Rule '{r2['id']}' on {fw_name} is redundant to '{r1['id']}'.",
                        'firewall_name': fw_name, 'firewall_type': self.firewall_data[fw_name]['type'],
                        'offending_rule': r2, 'primary_rule': r1
                    })
                else:
                    anomalies.append({
                        'type': 'shadowing', 'description': f"Rule '{r2['id']}' on {fw_name} is shadowed by '{r1['id']}'.",
                        'firewall_name': fw_name, 'firewall_type': self.firewall_data[fw_name]['type'],
                        'offending_rule': r2, 'primary_rule': r1
                    })
        return anomalies

    def analyze_inter_firewall(self) -> List[Dict]:
        anomalies, all_rules = [], []
        for fw_name, data in self.firewall_data.items():
            for i, rule in enumerate(data.get('rules', [])):
                rule['fw_name'] = fw_name
                rule['id'] = rule.get('name', f"rule-{i+1}")
                all_rules.append(rule)
        
        for i, r1 in enumerate(all_rules):
            for r2 in all_rules[i + 1:]:
                if r1['fw_name'] == r2['fw_name']: continue
                
                src1, dst1, svc1 = self._resolve_address(r1.get('source'), r1['fw_name']), self._resolve_address(r1.get('destination'), r1['fw_name']), self._resolve_service(r1.get('service'), r1['fw_name'])
                src2, dst2, svc2 = self._resolve_address(r2.get('source'), r2['fw_name']), self._resolve_address(r2.get('destination'), r2['fw_name']), self._resolve_service(r2.get('service'), r2['fw_name'])
                
                if not all([src1, dst1, svc1, src2, dst2, svc2]): continue
                
                if (bool(src1 & src2) and bool(dst1 & dst2) and self._services_overlap(svc1, svc2) and
                    self._get_canonical_zone(r1, r1['fw_name'], 'source') == self._get_canonical_zone(r2, r2['fw_name'], 'source') and
                    self._get_canonical_zone(r1, r1['fw_name'], 'destination') == self._get_canonical_zone(r2, r2['fw_name'], 'destination') and
                    r1.get('action') != r2.get('action')):
                    anomalies.append({'type': 'inter_firewall_conflict', 'description': f"Rule '{r1['id']}' on {r1['fw_name']} conflicts with rule '{r2['id']}' on {r2['fw_name']}."})
        
        graph = defaultdict(list)
        for rule in all_rules:
            if rule.get('action', '').lower() in ['permit', 'accept', 'allow']:
                src_zone, dst_zone = self._get_canonical_zone(rule, rule['fw_name'], 'source'), self._get_canonical_zone(rule, rule['fw_name'], 'destination')
                if src_zone != 'any' and dst_zone != 'any' and src_zone != dst_zone:
                    graph[src_zone].append(dst_zone)
        
        for node in list(graph.keys()):
            self._dfs_cycle_finder(graph, node, [], set(), anomalies)
        return anomalies

    def _dfs_cycle_finder(self, graph, start_node, path, visited_in_path, anomalies):
        path.append(start_node)
        visited_in_path.add(start_node)
        for neighbor in graph.get(start_node, []):
            if neighbor in visited_in_path:
                cycle_path = path[path.index(neighbor):] + [neighbor]
                cycle_key = tuple(sorted(cycle_path))
                if not any(anom.get('cycle_key') == cycle_key for anom in anomalies):
                    anomalies.append({
                        'type': 'cyclic_dependency',
                        'description': f"A cyclic dependency was detected: {' -> '.join(cycle_path)}",
                        'cycle_key': cycle_key
                    })
            else:
                self._dfs_cycle_finder(graph, neighbor, path, visited_in_path, anomalies)
        path.pop()
        visited_in_path.remove(start_node)

class AdvancedResolutionEngine:
    def generate_all_resolutions(self, anomalies_by_scope: Dict) -> List[Dict]:
        resolution_tasks = []
        for scope, anomalies in anomalies_by_scope.items():
            for anomaly in anomalies:
                if anomaly['type'] in ['redundancy', 'shadowing']:
                    task = self._generate_delete_rule_task(anomaly)
                    if task: resolution_tasks.append(task)
                else:
                    resolution_tasks.append({
                        'firewall_name': anomaly.get('fw_name', 'inter_firewall'),
                        'commands': [f"INFO: Manual review needed for {anomaly['type']}: {anomaly['description']}"],
                        'description': 'A complex anomaly that requires manual intervention.'
                    })
        return resolution_tasks

    def _generate_delete_rule_task(self, anomaly: Dict) -> Optional[Dict]:
        fw_type = anomaly.get('firewall_type')
        rule = anomaly.get('offending_rule')
        if not all([fw_type, rule]): return None

        commands = []
        if fw_type == 'cisco_asa':
            commands.append(f"no {rule['raw_line']}")
        elif fw_type == 'fortios':
            policy_id = rule['name'].replace('policy-', '')
            commands.extend([f"config firewall policy", f"delete {policy_id}", "end"])
        elif fw_type == 'paloalto':
            commands.append(f"delete rulebase security rules \"{rule['name']}\"")
        else:
            return None
        
        return {
            'firewall_name': anomaly['firewall_name'], 'commands': commands,
            'description': f"Resolve '{anomaly['type']}' by deleting rule '{rule.get('id', rule.get('name'))}'."
        }

class DeploymentEngine:
    def __init__(self, fw_configs: List[Dict], connectors: Dict):
        self.fw_configs = {c['name']: c for c in fw_configs}
        self.connectors = connectors

    def deploy(self, tasks: List[Dict], mode: str = 'dry_run'):
        if not tasks:
            logger.info("No deployment tasks to execute.")
            return
        
        for task in tasks:
            fw_name = task['firewall_name']
            if fw_name == 'inter_firewall': continue

            print("\n" + "-"*20 + f" TASK FOR: {fw_name} " + "-"*20)
            print(f"DESCRIPTION: {task['description']}")
            print("COMMANDS TO EXECUTE:")
            for cmd in task['commands']: print(f"  {cmd}")
            
            if mode == 'enforce' and "INFO:" not in task['commands'][0]:
                logger.warning(f"ENFORCING CHANGES ON {fw_name}. THIS IS RISKY.")
                try:
                    fw_conf = self.fw_configs[fw_name]
                    fw_type = fw_conf['type']
                    connector_class = self.connectors[fw_type]
                    connector = connector_class(fw_conf)
                    
                    if fw_type == 'cisco_asa':
                        full_commands = ['config terminal'] + task['commands'] + ['end']
                    elif fw_type == 'paloalto':
                        full_commands = ['configure'] + task['commands'] + ['commit', 'exit']
                    else:
                        full_commands = task['commands']
                    
                    self._run_config_commands(connector, full_commands)
                    logger.info(f"Successfully applied changes to {fw_name}.")
                except Exception as e:
                    logger.error(f"Failed to deploy to {fw_name}: {e}", exc_info=True)
            else:
                logger.info(f"Dry run for {fw_name}. No changes were applied.")

    def _run_config_commands(self, connector, commands):
        try:
            connector.connect()
            shell = connector.ssh.invoke_shell()
            time.sleep(2)
            shell.recv(65535)
            for command in commands:
                logger.info(f"Sending command: {command}")
                connector.send_command(shell, command)
                time.sleep(1)
            shell.close()
        finally:
            connector.disconnect()

def main():
    try:
        framework = FirewallFramework()
        framework.run()
    except Exception as e:
        logger.error(f"A critical error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()