#!/usr/bin/env python3
"""
优化的节点订阅更新脚本
支持多种协议，自动分离有效/失效节点
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
from urllib.parse import urlparse, urljoin
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
        """加载订阅链接"""
        if os.path.exists(self.subscriptions_file):
            with open(self.subscriptions_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
                self.raw_urls = [url for url in urls if not url.startswith('#')]
                logger.info(f"从 {self.subscriptions_file} 加载了 {len(self.raw_urls)} 个订阅链接")
        
        # 加载失效链接
        if os.path.exists(self.expired_file):
            with open(self.expired_file, 'r', encoding='utf-8') as f:
                self.expired_urls = {line.strip() for line in f if line.strip() and not line.startswith('#')}
    
    async def fetch_subscription(self, session, url: str) -> Optional[str]:
        """异步获取订阅内容"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with session.get(url, headers=headers, timeout=timeout) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # 检查内容是否有效
                    if not content or len(content.strip()) < 10:
                        logger.warning(f"URL返回内容过短: {url}")
                        return None
                    
                    # 检查是否是base64编码
                    if self.is_base64(content):
                        try:
                            content = base64.b64decode(content).decode('utf-8')
                        except:
                            pass
                    
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
        try:
            if len(s) % 4 != 0:
                return False
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
                return False
            base64.b64decode(s)
            return True
        except:
            return False
    
    def parse_content(self, content: str) -> Dict[str, List[str]]:
        """解析订阅内容，识别各种协议"""
        result = {
            'ss': [], 'ssr': [], 'vmess': [], 'vless': [], 
            'trojan': [], 'hysteria': [], 'hysteria2': [],
            'tuic': [], 'wireguard': [], 'clash': []
        }
        
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        
        for line in lines:
            # 尝试解析为各种协议
            node = self.parse_node(line)
            if node:
                result[node['type']].append(node['config'])
        
        return result
    
    def parse_node(self, config: str) -> Optional[Dict]:
        """解析单个节点配置"""
        config = config.strip()
        
        # 1. 解析 Clash 配置
        if config.startswith('http://') or config.startswith('https://'):
            return {'type': 'clash', 'config': config}
        
        # 2. 解析 Shadowsocks (ss://)
        if config.startswith('ss://'):
            return {'type': 'ss', 'config': config}
        
        # 3. 解析 ShadowsocksR (ssr://)
        if config.startswith('ssr://'):
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
        if 'hysteria://' in config.lower():
            if 'hysteria2://' in config.lower():
                return {'type': 'hysteria2', 'config': config}
            return {'type': 'hysteria', 'config': config}
        
        # 8. 解析 TUIC
        if config.lower().startswith('tuic://'):
            return {'type': 'tuic', 'config': config}
        
        # 9. 解析 WireGuard
        if '[interface]' in config.lower() or 'privatekey' in config.lower():
            return {'type': 'wireguard', 'config': config}
        
        # 10. 尝试解析为 base64 编码的 JSON (Clash 配置)
        try:
            decoded = base64.b64decode(config + '=' * (-len(config) % 4)).decode('utf-8')
            if 'proxies:' in decoded or 'Proxy:' in decoded or 'proxy-groups:' in decoded:
                return {'type': 'clash', 'config': config}
        except:
            pass
        
        return None
    
    async def process_urls(self):
        """处理所有URL"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            url_map = {}
            
            # 创建所有任务
            for url in self.raw_urls:
                task = asyncio.create_task(self.fetch_subscription(session, url))
                tasks.append(task)
                url_map[task] = url
            
            # 处理结果
            for task in asyncio.as_completed(tasks):
                url = url_map[task]
                try:
                    content = await task
                    
                    if content:
                        self.active_urls.add(url)
                        if url in self.expired_urls:
                            self.expired_urls.remove(url)
                        
                        # 解析内容
                        parsed = self.parse_content(content)
                        for protocol, nodes in parsed.items():
                            if nodes:
                                self.nodes[protocol].extend(nodes)
                                logger.info(f"从 {url} 解析到 {len(nodes)} 个 {protocol.upper()} 节点")
                    
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
        stats = []
        
        for protocol, nodes in self.nodes.items():
            if nodes:
                # 去重
                unique_nodes = list(dict.fromkeys(nodes))
                
                # 保存节点
                filename = f"active_{protocol}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    for node in unique_nodes:
                        f.write(f"{node}\n")
                
                count = len(unique_nodes)
                total_nodes += count
                stats.append(f"[{protocol.upper()}] 有效 {count} 条")
                logger.info(f"[写入] {filename}: {count} 条")
        
        # 保存合并文件
        all_nodes = []
        for protocol, nodes in self.nodes.items():
            all_nodes.extend(nodes)
        
        if all_nodes:
            all_nodes = list(dict.fromkeys(all_nodes))
            with open('all.txt', 'w', encoding='utf-8') as f:
                for node in all_nodes:
                    f.write(f"{node}\n")
            
            with open('merged_all.txt', 'w', encoding='utf-8') as f:
                for node in all_nodes:
                    f.write(f"{node}\n")
            
            # 生成Clash配置
            self.generate_clash_config(all_nodes)
        
        # 生成统计信息
        stats_text = "\n".join(stats)
        stats_summary = f"""
[分组] 有效订阅: {len(self.active_urls)} 条
[分组] 失效订阅: {len(self.expired_urls)} 条
[统计] 总节点数: {total_nodes} 条

{stats_text}
[完成] all.txt: {len(all_nodes)} 条
"""
        
        with open('stats.txt', 'w', encoding='utf-8') as f:
            f.write(stats_summary)
        
        print(stats_summary)
    
    def generate_clash_config(self, nodes: List[str]):
        """生成Clash配置文件"""
        clash_config = {
            'port': 7890,
            'socks-port': 7891,
            'allow-lan': False,
            'mode': 'Rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            'proxies': [],
            'proxy-groups': [],
            'rules': [
                'DOMAIN-SUFFIX,google.com,PROXY',
                'DOMAIN-KEYWORD,github,PROXY',
                'IP-CIDR,127.0.0.0/8,DIRECT',
                'GEOIP,CN,DIRECT',
                'MATCH,PROXY'
            ]
        }
        
        proxy_index = 1
        for node in nodes:
            if node.startswith('ss://'):
                try:
                    clash_config['proxies'].append({
                        'name': f'SS-{proxy_index}',
                        'type': 'ss',
                        'server': 'server_address',  # 需要从节点解析
                        'port': 443,
                        'cipher': 'aes-256-gcm',
                        'password': 'password'
                    })
                    proxy_index += 1
                except:
                    pass
        
        if clash_config['proxies']:
            clash_config['proxy-groups'] = [
                {
                    'name': 'PROXY',
                    'type': 'select',
                    'proxies': [p['name'] for p in clash_config['proxies']]
                },
                {
                    'name': 'Auto',
                    'type': 'url-test',
                    'proxies': [p['name'] for p in clash_config['proxies']],
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300
                }
            ]
            
            with open('clash.yaml', 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False)
            
            logger.info(f"[写入] clash.yaml: 包含 {len(clash_config['proxies'])} 个代理")

async def main():
    """主函数"""
    logger.info("开始更新节点订阅...")
    
    manager = NodeManager()
    manager.load_urls()
    
    if not manager.raw_urls:
        logger.warning("没有找到订阅链接，请在 subscriptions.txt 中添加链接")
        return
    
    await manager.process_urls()
    manager.save_results()
    
    logger.info("节点更新完成！")

if __name__ == "__main__":
    asyncio.run(main())
