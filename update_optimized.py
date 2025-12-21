#!/usr/bin/env python3
"""
简化的节点订阅更新脚本
支持多种协议，自动分离有效/失效节点，智能去重
"""

import os
import re
import sys
import time
import yaml
import json
import base64
import asyncio
import aiohttp
import requests
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
from typing import List, Dict, Tuple, Set, Optional
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('update.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NodeManager:
    def __init__(self):
        self.active_urls = set()  # 当前有效的订阅URL
        self.expired_urls = set()  # 失效的订阅URL
        self.nodes = {
            'ss': [], 'ssr': [], 'vmess': [], 'vless': [], 
            'trojan': [], 'hysteria': [], 'hysteria2': [],
            'tuic': [], 'wireguard': [], 'clash': []
        }
        self.raw_urls = []  # 原始订阅链接
        self.subscriptions_file = 'subscriptions.txt'
        self.expired_file = 'expired_subscriptions.txt'
        
        def load_urls(self):
        """加载订阅链接，并去重写回文件"""
        if os.path.exists(self.subscriptions_file):
            with open(self.subscriptions_file, 'r', encoding='utf-8') as f:
                # 读取原始内容，保留注释和空行
                original_lines = f.readlines()
                
                # 提取有效的URL
                urls = []
                valid_lines = []  # 用于存储有效的行（非注释、非空行）
                
                for line in original_lines:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        urls.append(stripped)
                        valid_lines.append(line)
                
                # 基础去重：基于字符串完全一致
                before_count = len(urls)
                unique_urls = list(dict.fromkeys(urls))
                after_count = len(unique_urls)
                
                if before_count > after_count:
                    removed = before_count - after_count
                    logger.info(f"[订阅去重] 从 {before_count} 个链接中去除了 {removed} 个重复链接，剩余 {after_count} 个")
                    
                    # 将去重后的链接写回文件
                    self._write_deduplicated_subscriptions(original_lines, unique_urls)
                else:
                    logger.info(f"从 {self.subscriptions_file} 加载了 {len(unique_urls)} 个订阅链接")
                
                self.raw_urls = unique_urls
        
        # 加载失效链接
        if os.path.exists(self.expired_file):
            with open(self.expired_file, 'r', encoding='utf-8') as f:
                expired_urls = {line.strip() for line in f if line.strip() and not line.startswith('#')}
                # 失效链接也进行基础去重
                self.expired_urls = set(expired_urls)
                logger.info(f"从 {self.expired_file} 加载了 {len(self.expired_urls)} 个失效链接")
    
    def _write_deduplicated_subscriptions(self, original_lines: List[str], unique_urls: List[str]):
        """将去重后的订阅链接写回文件"""
        try:
            # 构建新内容
            new_content_lines = []
            url_index = 0
            url_set = set(unique_urls)  # 用于快速查找
            
            for line in original_lines:
                stripped = line.strip()
                if not stripped:  # 空行
                    new_content_lines.append(line)
                elif stripped.startswith('#'):  # 注释行
                    new_content_lines.append(line)
                else:  # URL行
                    if stripped in url_set and url_index < len(unique_urls):
                        # 找到匹配的URL，添加
                        new_content_lines.append(unique_urls[url_index] + '\n')
                        url_index += 1
                        # 从集合中移除，避免重复添加
                        url_set.remove(stripped)
            
            # 写入文件
            with open(self.subscriptions_file, 'w', encoding='utf-8') as f:
                f.writelines(new_content_lines)
            
            logger.info(f"[文件更新] 已将去重后的订阅链接写回 {self.subscriptions_file}")
            
        except Exception as e:
            logger.error(f"写回订阅文件失败: {e}")

    async def fetch_subscription(self, session, url: str) -> Optional[str]:
        """异步获取订阅内容"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with session.get(url, headers=headers, timeout=timeout, ssl=False) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    # 根据不同的内容类型处理
                    if 'application/octet-stream' in content_type or 'text/plain' in content_type:
                        content = await response.text()
                    else:
                        # 尝试按二进制读取，然后解码
                        content_bytes = await response.read()
                        try:
                            # 尝试UTF-8解码
                            content = content_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                # 尝试其他编码
                                content = content_bytes.decode('gbk')
                            except:
                                # 如果都失败，使用原始字节
                                content = str(content_bytes)
                    
                    # 检查内容是否有效
                    if not content or len(content.strip()) < 10:
                        logger.warning(f"URL返回内容过短: {url}")
                        return None
                    
                    # 检查并处理base64编码
                    cleaned_content = content.strip()
                    if self.is_base64(cleaned_content):
                        try:
                            # 添加padding
                            padding = 4 - len(cleaned_content) % 4
                            if padding != 4:
                                cleaned_content += '=' * padding
                            decoded = base64.b64decode(cleaned_content)
                            content = decoded.decode('utf-8', errors='ignore')
                        except Exception as e:
                            logger.debug(f"Base64解码失败，使用原始内容: {e}")
                    
                    return content
                else:
                    logger.warning(f"HTTP错误 {response.status}: {url}")
                    return None
                    
        except asyncio.TimeoutError:
            logger.warning(f"请求超时: {url}")
            return None
        except Exception as e:
            logger.warning(f"获取订阅失败 {url}: {str(e)}")
            return None
    
    def is_base64(self, s: str) -> bool:
        """检查字符串是否是base64编码"""
        s = s.strip()
        if len(s) < 20:  # 太短的字符串不可能是base64节点列表
            return False
        
        # 移除可能的URL安全base64字符
        s = s.replace('-', '+').replace('_', '/')
        
        # 检查base64特征
        pattern = r'^[A-Za-z0-9+/]+={0,2}$'
        if not re.match(pattern, s):
            return False
        
        # 检查长度是否为4的倍数
        if len(s) % 4 != 0:
            return False
            
        return True
    
    def parse_content(self, content: str, url: str) -> Dict[str, List[str]]:
        """解析订阅内容，识别各种协议"""
        result = {key: [] for key in self.nodes.keys()}
        
        # 先尝试解析为Clash配置
        if self.is_clash_config(content, url):
            logger.info(f"检测到Clash配置: {url}")
            clash_nodes = self.extract_clash_nodes(content, url)
            if clash_nodes:
                for node_type, nodes in clash_nodes.items():
                    if node_type in result:
                        result[node_type].extend(nodes)
                return result
        
        # 按行处理
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        
        for line in lines:
            # 尝试解析为各种协议
            node_info = self.parse_node(line)
            if node_info:
                result[node_info['type']].append(node_info['config'])
            else:
                # 如果不是标准格式，尝试base64解码
                if self.is_base64(line):
                    try:
                        decoded = base64.b64decode(line + '=' * (-len(line) % 4))
                        decoded_str = decoded.decode('utf-8', errors='ignore')
                        decoded_lines = decoded_str.split('\n')
                        for decoded_line in decoded_lines:
                            decoded_line = decoded_line.strip()
                            if decoded_line:
                                node_info = self.parse_node(decoded_line)
                                if node_info:
                                    result[node_info['type']].append(node_info['config'])
                    except:
                        pass
        
        return result
    
    def is_clash_config(self, content: str, url: str) -> bool:
        """检查是否是Clash配置"""
        # 检查URL是否包含clash关键词
        url_lower = url.lower()
        if 'clash' in url_lower or 'yaml' in url_lower or 'yml' in url_lower:
            return True
        
        # 检查内容是否包含Clash关键词
        content_lower = content.lower()
        if 'proxies:' in content_lower or 'proxy-groups:' in content_lower or 'rules:' in content_lower:
            return True
        
        # 尝试解析为YAML
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and ('proxies' in data or 'Proxy' in data):
                return True
        except:
            pass
        
        return False
    
    def extract_clash_nodes(self, content: str, url: str) -> Dict[str, List[str]]:
        """从Clash配置中提取节点"""
        result = {key: [] for key in self.nodes.keys()}
        
        try:
            # 尝试解析YAML
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return result
            
            # 获取代理列表
            proxies = data.get('proxies') or data.get('Proxy') or []
            if not isinstance(proxies, list):
                return result
            
            for proxy in proxies:
                if not isinstance(proxy, dict):
                    continue
                    
                proxy_type = str(proxy.get('type', '')).lower()
                name = proxy.get('name', '')
                server = proxy.get('server', '')
                port = proxy.get('port', '')
                
                if not server or not port:
                    continue
                
                # 根据类型生成对应的链接
                if proxy_type == 'ss':
                    # shadowsocks格式: ss://method:password@server:port#name
                    password = proxy.get('password', '')
                    cipher = proxy.get('cipher', '')
                    if password and cipher and server and port:
                        encoded = base64.b64encode(f"{cipher}:{password}".encode()).decode()
                        node_url = f"ss://{encoded}@{server}:{port}#{name}"
                        result['ss'].append(node_url)
                
                elif proxy_type == 'vmess':
                    # vmess格式
                    uuid = proxy.get('uuid', '')
                    if uuid and server and port:
                        config = {
                            "v": "2",
                            "ps": name,
                            "add": server,
                            "port": port,
                            "id": uuid,
                            "aid": proxy.get('alterId', 0),
                            "scy": proxy.get('cipher', 'auto'),
                            "net": proxy.get('network', 'tcp'),
                            "type": proxy.get('type', 'none'),
                            "host": proxy.get('servername', '') or proxy.get('host', ''),
                            "path": proxy.get('path', ''),
                            "tls": proxy.get('tls', ''),
                            "sni": proxy.get('sni', '')
                        }
                        config_str = json.dumps(config, ensure_ascii=False, separators=(',', ':'))
                        encoded = base64.b64encode(config_str.encode()).decode()
                        node_url = f"vmess://{encoded}"
                        result['vmess'].append(node_url)
                
                elif proxy_type == 'trojan':
                    # trojan格式: trojan://password@server:port#name
                    password = proxy.get('password', '')
                    if password and server and port:
                        node_url = f"trojan://{password}@{server}:{port}#{name}"
                        result['trojan'].append(node_url)
                
                elif proxy_type == 'vless':
                    # vless格式
                    uuid = proxy.get('uuid', '')
                    if uuid and server and port:
                        node_url = f"vless://{uuid}@{server}:{port}?type={proxy.get('network', 'tcp')}#{name}"
                        result['vless'].append(node_url)
                
                elif proxy_type == 'hysteria':
                    # hysteria格式
                    node_url = f"hysteria://{server}:{port}?protocol={proxy.get('protocol', 'udp')}#{name}"
                    result['hysteria'].append(node_url)
                
                elif proxy_type == 'tuic':
                    # tuic格式
                    uuid = proxy.get('uuid', '') or proxy.get('password', '')
                    if uuid and server and port:
                        node_url = f"tuic://{uuid}@{server}:{port}#{name}"
                        result['tuic'].append(node_url)
            
            logger.info(f"从Clash配置中提取了 {sum(len(v) for v in result.values())} 个节点")
            
        except Exception as e:
            logger.error(f"解析Clash配置失败: {e}")
        
        return result
    
    def parse_node(self, config: str) -> Optional[Dict]:
        """解析单个节点配置"""
        config = config.strip()
        if not config:
            return None
        
        # 1. 解析 Clash 配置URL
        if config.startswith('http://') or config.startswith('https://'):
            if 'clash' in config.lower() or 'yaml' in config.lower() or 'yml' in config.lower():
                return {'type': 'clash', 'config': config}
        
        # 2. 解析 Shadowsocks (ss://)
        if config.lower().startswith('ss://'):
            return {'type': 'ss', 'config': config}
        
        # 3. 解析 ShadowsocksR (ssr://)
        if config.lower().startswith('ssr://'):
            return {'type': 'ssr', 'config': config}
        
        # 4. 解析 VMess (vmess://)
        if config.lower().startswith('vmess://'):
            return {'type': 'vmess', 'config': config}
        
        # 5. 解析 VLess (vless://)
        if config.lower().startswith('vless://'):
            return {'type': 'vless', 'config': config}
        
        # 6. 解析 Trojan (trojan://)
        if config.lower().startswith('trojan://'):
            return {'type': 'trojan', 'config': config}
        
        # 7. 解析 Hysteria
        if config.lower().startswith('hysteria://'):
            return {'type': 'hysteria', 'config': config}
        
        # 8. 解析 Hysteria2
        if config.lower().startswith('hysteria2://'):
            return {'type': 'hysteria2', 'config': config}
        
        # 9. 解析 TUIC
        if config.lower().startswith('tuic://'):
            return {'type': 'tuic', 'config': config}
        
        # 10. 解析 WireGuard
        if '[interface]' in config.lower() or 'privatekey' in config.lower():
            return {'type': 'wireguard', 'config': config}
        
        # 11. 尝试解析为各种协议的base64
        if len(config) > 50 and '://' not in config:
            # 可能是base64编码的vmess
            if config.count('.') > 2:  # 有多个点，可能是base64
                try:
                    decoded = base64.b64decode(config + '=' * (-len(config) % 4))
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                    if 'vmess://' in decoded_str.lower():
                        return {'type': 'vmess', 'config': config}
                except:
                    pass
        
        return None
    
    def extract_node_info(self, config: str) -> Optional[Dict]:
        """解析节点配置，提取关键信息用于去重"""
        config = config.strip()
        if not config:
            return None
        
        try:
            # 1. Shadowsocks (ss://)
            if config.lower().startswith('ss://'):
                # 格式: ss://base64@host:port#name
                try:
                    if '#' in config:
                        base_config, name = config.split('#', 1)
                    else:
                        base_config, name = config, ''
                    
                    if '@' in base_config:
                        encoded_part, server_part = base_config[5:].split('@', 1)
                    else:
                        # 可能是没有@的格式
                        encoded_part = base_config[5:]
                        server_part = ""
                    
                    # 解码base64部分
                    try:
                        padding = 4 - len(encoded_part) % 4
                        if padding != 4:
                            encoded_part += '=' * padding
                        decoded = base64.b64decode(encoded_part).decode('utf-8', errors='ignore')
                        if ':' in decoded:
                            method = decoded.split(':')[0]
                        else:
                            method = 'unknown'
                    except:
                        method = 'unknown'
                    
                    # 提取服务器和端口
                    if ':' in server_part:
                        server = server_part.split(':')[0]
                        port_part = server_part.split(':')[1]
                        if '/' in port_part:
                            port = port_part.split('/')[0]
                        else:
                            port = port_part
                    else:
                        server, port = 'unknown', '0'
                    
                    return {
                        'type': 'ss',
                        'server': server,
                        'port': port,
                        'method': method,
                        'original': config
                    }
                except:
                    return None
            
            # 2. VMess (vmess://)
            elif config.lower().startswith('vmess://'):
                # 格式: vmess://base64
                encoded = config[8:]
                try:
                    padding = 4 - len(encoded) % 4
                    if padding != 4:
                        encoded += '=' * padding
                    decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                    data = json.loads(decoded)
                    server = data.get('add', '')
                    port = str(data.get('port', ''))
                    uuid = data.get('id', '')
                    if server and port and uuid:
                        return {
                            'type': 'vmess',
                            'server': server,
                            'port': port,
                            'uuid': uuid,
                            'original': config
                        }
                except:
                    return None
            
            # 3. VLess (vless://)
            elif config.lower().startswith('vless://'):
                # 格式: vless://uuid@host:port?params#name
                try:
                    parts = config[8:].split('@', 1)
                    if len(parts) == 2:
                        uuid = parts[0]
                        rest = parts[1]
                        
                        # 移除名称
                        if '#' in rest:
                            rest = rest.split('#')[0]
                        
                        # 移除参数
                        if '?' in rest:
                            server_port = rest.split('?')[0]
                        else:
                            server_port = rest
                        
                        if ':' in server_port:
                            server = server_port.split(':')[0]
                            port = server_port.split(':')[1]
                        else:
                            server, port = 'unknown', '0'
                        
                        return {
                            'type': 'vless',
                            'server': server,
                            'port': port,
                            'uuid': uuid,
                            'original': config
                        }
                except:
                    return None
            
            # 4. Trojan (trojan://)
            elif config.lower().startswith('trojan://'):
                # 格式: trojan://password@host:port?params#name
                try:
                    parts = config[9:].split('@', 1)
                    if len(parts) == 2:
                        password = parts[0]
                        rest = parts[1]
                        
                        # 移除名称
                        if '#' in rest:
                            rest = rest.split('#')[0]
                        
                        # 移除参数
                        if '?' in rest:
                            server_port = rest.split('?')[0]
                        else:
                            server_port = rest
                        
                        if ':' in server_port:
                            server = server_port.split(':')[0]
                            port = server_port.split(':')[1]
                        else:
                            server, port = 'unknown', '0'
                        
                        return {
                            'type': 'trojan',
                            'server': server,
                            'port': port,
                            'password': password,
                            'original': config
                        }
                except:
                    return None
            
            # 5. ShadowsocksR (ssr://)
            elif config.lower().startswith('ssr://'):
                # 格式: ssr://base64
                encoded = config[6:]
                try:
                    padding = 4 - len(encoded) % 4
                    if padding != 4:
                        encoded += '=' * padding
                    decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                    
                    # SSR格式: server:port:protocol:method:obfs:base64(password)/?params
                    if '/' in decoded:
                        main_part = decoded.split('/')[0]
                    else:
                        main_part = decoded
                    
                    parts = main_part.split(':')
                    if len(parts) >= 6:
                        server = parts[0]
                        port = parts[1]
                        method = parts[3] if len(parts) > 3 else 'unknown'
                        
                        return {
                            'type': 'ssr',
                            'server': server,
                            'port': port,
                            'method': method,
                            'original': config
                        }
                except:
                    return None
            
            # 6. Hysteria
            elif config.lower().startswith('hysteria://') or config.lower().startswith('hysteria2://'):
                # 格式: hysteria://host:port?params#name
                try:
                    is_hysteria2 = config.lower().startswith('hysteria2://')
                    prefix_len = 11 if is_hysteria2 else 10
                    
                    rest = config[prefix_len:]
                    
                    # 移除名称
                    if '#' in rest:
                        rest = rest.split('#')[0]
                    
                    # 移除参数
                    if '?' in rest:
                        server_port = rest.split('?')[0]
                    else:
                        server_port = rest
                    
                    if ':' in server_port:
                        server = server_port.split(':')[0]
                        port = server_port.split(':')[1]
                    else:
                        server, port = 'unknown', '0'
                    
                    return {
                        'type': 'hysteria2' if is_hysteria2 else 'hysteria',
                        'server': server,
                        'port': port,
                        'original': config
                    }
                except:
                    return None
            
            # 7. TUIC
            elif config.lower().startswith('tuic://'):
                # 格式: tuic://uuid@host:port?params#name
                try:
                    parts = config[7:].split('@', 1)
                    if len(parts) == 2:
                        uuid = parts[0]
                        rest = parts[1]
                        
                        # 移除名称
                        if '#' in rest:
                            rest = rest.split('#')[0]
                        
                        # 移除参数
                        if '?' in rest:
                            server_port = rest.split('?')[0]
                        else:
                            server_port = rest
                        
                        if ':' in server_port:
                            server = server_port.split(':')[0]
                            port = server_port.split(':')[1]
                        else:
                            server, port = 'unknown', '0'
                        
                        return {
                            'type': 'tuic',
                            'server': server,
                            'port': port,
                            'uuid': uuid,
                            'original': config
                        }
                except:
                    return None
            
            # 8. 订阅链接
            elif config.startswith('http://') or config.startswith('https://'):
                return None
            
        except Exception as e:
            logger.debug(f"解析节点信息失败 {config[:50]}...: {e}")
        
        return None
    
    def deduplicate_nodes_by_server(self, nodes: List[str]) -> List[str]:
        """基于服务器信息去重节点"""
        seen = set()
        unique_nodes = []
        
        for node in nodes:
            node_info = self.extract_node_info(node)
            if node_info:
                # 创建去重键
                if node_info['type'] in ['vmess', 'vless']:
                    # 对于VMess/VLess，使用服务器+端口+uuid
                    dedup_key = f"{node_info['type']}:{node_info['server'].lower()}:{node_info['port']}:{node_info.get('uuid', '').lower()}"
                elif node_info['type'] in ['trojan', 'tuic']:
                    # 对于Trojan/TUIC，使用服务器+端口+密码/uuid
                    auth_key = node_info.get('password', '') or node_info.get('uuid', '')
                    dedup_key = f"{node_info['type']}:{node_info['server'].lower()}:{node_info['port']}:{auth_key.lower()}"
                elif node_info['type'] in ['ss', 'ssr']:
                    # 对于SS/SSR，使用服务器+端口+加密方法
                    dedup_key = f"{node_info['type']}:{node_info['server'].lower()}:{node_info['port']}:{node_info.get('method', '').lower()}"
                else:
                    # 其他协议，使用服务器+端口
                    dedup_key = f"{node_info['type']}:{node_info['server'].lower()}:{node_info['port']}"
                
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    unique_nodes.append(node)
            else:
                # 如果无法解析，保留原始节点
                unique_nodes.append(node)
        
        return unique_nodes
    
    async def process_urls(self):
        """处理所有URL"""
        if not self.raw_urls:
            logger.warning("没有找到订阅链接")
            return
        
        logger.info(f"开始处理 {len(self.raw_urls)} 个订阅链接...")
        
        async with aiohttp.ClientSession() as session:
            # 创建所有任务
            tasks = []
            for url in self.raw_urls:
                task = asyncio.create_task(self.fetch_subscription(session, url))
                tasks.append((task, url))
            
            # 处理结果
            for task, url in tasks:
                try:
                    content = await task
                    
                    if content:
                        logger.info(f"成功获取订阅: {url}")
                        self.active_urls.add(url)
                        if url in self.expired_urls:
                            self.expired_urls.remove(url)
                            logger.info(f"从失效列表中移除: {url}")
                        
                        # 解析内容
                        parsed = self.parse_content(content, url)
                        node_count = 0
                        for protocol, nodes in parsed.items():
                            if nodes:
                                unique_nodes = list(dict.fromkeys(nodes))  # 去重
                                self.nodes[protocol].extend(unique_nodes)
                                node_count += len(unique_nodes)
                                logger.info(f"  解析到 {len(unique_nodes)} 个 {protocol.upper()} 节点")
                        
                        if node_count == 0:
                            logger.warning(f"  警告: 未解析到任何节点，可能是格式不支持")
                    
                    else:
                        logger.warning(f"订阅失效: {url}")
                        if url in self.active_urls:
                            self.active_urls.remove(url)
                        self.expired_urls.add(url)
                        
                except Exception as e:
                    logger.error(f"处理URL失败 {url}: {str(e)}")
                    if url in self.active_urls:
                        self.active_urls.remove(url)
                    self.expired_urls.add(url)
    
    def save_results(self):
        """保存结果到文件"""
        # 保存有效订阅链接
        with open('active_subscriptions.txt', 'w', encoding='utf-8') as f:
            for url in sorted(self.active_urls):
                f.write(f"{url}\n")
        
        # 保存失效订阅链接
        with open('expired_subscriptions.txt', 'w', encoding='utf-8') as f:
            for url in sorted(self.expired_urls):
                f.write(f"{url}\n")
        
        # 按协议保存节点
        total_nodes = 0
        stats_lines = []
        
        for protocol, nodes in self.nodes.items():
            if nodes:
                # 首先基于原始配置去重
                unique_nodes = list(dict.fromkeys(nodes))
                
                # 然后基于服务器信息去重
                if protocol in ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic']:
                    before_count = len(unique_nodes)
                    unique_nodes = self.deduplicate_nodes_by_server(unique_nodes)
                    after_count = len(unique_nodes)
                    
                    # 显示去重统计
                    if before_count > after_count:
                        removed = before_count - after_count
                        percentage = (removed / before_count) * 100
                        logger.info(f"[去重] {protocol.upper()}: {before_count} → {after_count} (移除 {removed} 个, {percentage:.1f}%)")
                
                count = len(unique_nodes)
                total_nodes += count
                
                # 保存节点
                filename = f"{protocol}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    for node in unique_nodes:
                        f.write(f"{node}\n")
                
                stats_lines.append(f"[{protocol.upper()}] 有效 {count} 条")
                logger.info(f"[写入] {filename}: {count} 条 (已去重)")
            else:
                # 创建空文件以便统计
                filename = f"{protocol}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    pass
        
        # 保存合并文件 - 保存为 all.txt
        all_nodes = []
        for protocol, nodes in self.nodes.items():
            all_nodes.extend(nodes)
        
        if all_nodes:
            # 首先基于原始配置去重
            all_nodes = list(dict.fromkeys(all_nodes))
            
            # 然后基于服务器信息去重
            before_all_count = len(all_nodes)
            all_nodes = self.deduplicate_nodes_by_server(all_nodes)
            all_count = len(all_nodes)
            
            # 显示合并去重统计
            if before_all_count > all_count:
                removed = before_all_count - all_count
                percentage = (removed / before_all_count) * 100
                logger.info(f"[合并去重] 总数: {before_all_count} → {all_count} (移除 {removed} 个, {percentage:.1f}%)")
            
            # 保存合并文件
            with open('all.txt', 'w', encoding='utf-8') as f:
                for node in all_nodes:
                    f.write(f"{node}\n")
            
            # 生成统计信息
            separator = "─" * 40
            stats_summary = f"""
{separator}
📊 节点订阅统计
{separator}
📈 有效订阅: {len(self.active_urls):<4} 条
📉 失效订阅: {len(self.expired_urls):<4} 条
📦 总节点数: {total_nodes:<6} 条 (已去重)
{separator}
📁 节点分布:
{separator}
{chr(10).join(stats_lines)}
{separator}
💾 合并文件: all.txt ({all_count} 条, 已去重)
{separator}
"""
        else:
            stats_summary = f"""
{separator}
📊 节点订阅统计
{separator}
📈 有效订阅: {len(self.active_urls):<4} 条
📉 失效订阅: {len(self.expired_urls):<4} 条
📦 总节点数: 0 条
{separator}
⚠️ 未解析到任何有效节点
{separator}
"""
        
        with open('stats.txt', 'w', encoding='utf-8') as f:
            f.write(stats_summary)
        
        print(stats_summary)
        logger.info(f"更新完成！有效订阅: {len(self.active_urls)}, 失效订阅: {len(self.expired_urls)}, 总节点: {total_nodes}")

async def main():
    """主函数"""
    logger.info("开始更新节点订阅...")
    
    manager = NodeManager()
    manager.load_urls()
    
    if not manager.raw_urls:
        logger.warning("没有找到订阅链接，请在 subscriptions.txt 中添加链接")
        print("⚠️ 请在 subscriptions.txt 文件中添加订阅链接")
        with open('subscriptions.txt', 'w', encoding='utf-8') as f:
            f.write("# 在此添加你的订阅链接，每行一个\n")
            f.write("# 例如：\n")
            f.write("# https://example.com/subscribe\n")
        return
    
    await manager.process_urls()
    manager.save_results()
    
    logger.info("节点更新完成！")

if __name__ == "__main__":
    asyncio.run(main())
