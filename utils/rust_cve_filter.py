#!/usr/bin/env python3
"""
CVE 筛选脚本 - 实用版
使用多种数据源来获取 Rust 相关的 CVE 信息
筛选出没有 rustsec 引用的条目
"""

import requests
from bs4 import BeautifulSoup
import time
import json
import csv
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
import argparse


@dataclass
class CVEInfo:
    cve_id: str
    title: str
    description: str
    severity: str
    publish_date: str
    references: List[str]
    has_rustsec: bool
    source: str


class MultiSourceCVECollector:
    """多数据源 CVE 收集器"""
    
    def __init__(self, delay: float = 2.0):
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def get_from_nvd(self, keyword: str = "rust") -> List[CVEInfo]:
        """从 NVD (National Vulnerability Database) 获取 CVE 信息"""
        print(f"\n从 NVD 获取 {keyword} 相关 CVE...")
        
        cves = []
        
        try:
            # NVD API v2
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': 2000,  # 限制结果数量
                'startIndex': 0
            }
            
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for cve_item in data.get('vulnerabilities', []):
                    cve_data = cve_item.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    
                    # 提取描述
                    descriptions = cve_data.get('descriptions', [])
                    description = ""
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # 提取引用链接
                    references = []
                    refs_data = cve_data.get('references', [])
                    for ref in refs_data:
                        url_ref = ref.get('url', '')
                        if url_ref:
                            references.append(url_ref)
                    
                    # 检查是否包含 rustsec 引用 - 更严格的检查
                    has_rustsec = False
                    
                    # 检查引用链接中是否包含 rustsec
                    for ref in references:
                        ref_lower = ref.lower()
                        if ('rustsec.org' in ref_lower or 
                            'rustsec' in ref_lower or 
                            '/rustsec/' in ref_lower or
                            'RUSTSEC-' in ref):  # 检查 RUSTSEC ID
                            has_rustsec = True
                            break
                    
                    # 检查描述中是否包含 rustsec
                    if not has_rustsec:
                        desc_lower = description.lower()
                        if 'rustsec' in desc_lower:
                            has_rustsec = True
                    
                    # 提取严重性评分
                    severity = "未知"
                    metrics = cve_data.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss = metrics['cvssMetricV31'][0]['cvssData']
                        severity = cvss.get('baseSeverity', '未知')
                    elif 'cvssMetricV30' in metrics:
                        cvss = metrics['cvssMetricV30'][0]['cvssData']
                        severity = cvss.get('baseSeverity', '未知')
                    
                    # 提取发布日期
                    publish_date = cve_data.get('published', '未知')
                    
                    cve_info = CVEInfo(
                        cve_id=cve_id,
                        title=f"{cve_id} - {description[:100]}..." if len(description) > 100 else description,
                        description=description,
                        severity=severity,
                        publish_date=publish_date,
                        references=references,
                        has_rustsec=has_rustsec,
                        source="NVD"
                    )
                    
                    cves.append(cve_info)
                
                print(f"从 NVD 获取到 {len(cves)} 个 CVE")
                
            else:
                print(f"NVD API 请求失败: {response.status_code}")
                
        except Exception as e:
            print(f"从 NVD 获取数据失败: {e}")
        
        return cves
    
    def get_from_cve_org_note(self) -> List[CVEInfo]:
        """
        注意：cve.org 网站使用 JavaScript 动态加载内容，无法通过简单的HTTP请求获取数据
        建议使用 NVD API 或其他数据源
        如果需要从 cve.org 获取数据，需要使用 Selenium 等浏览器自动化工具
        """
        print(f"\n注意: cve.org 是 JavaScript 单页应用，无法直接爬取")
        print(f"建议使用 NVD API (已实现) 或 Selenium 浏览器自动化")
        return []
    
    def get_from_github_advisories(self) -> List[CVEInfo]:
        """从 GitHub Security Advisories 获取 Rust 相关 CVE"""
        print(f"\n从 GitHub Security Advisories 获取 Rust CVE...")
        
        cves = []
        
        try:
            # GitHub GraphQL API 需要认证，这里使用搜索页面
            url = "https://github.com/advisories"
            params = {
                'query': 'ecosystem:rust',
            }
            
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # 查找 advisory 条目
                for advisory in soup.find_all('div', class_=lambda x: x and 'advisory' in x.lower()):
                    try:
                        # 提取 CVE ID
                        cve_link = advisory.find('a', href=lambda x: x and 'CVE-' in x)
                        if not cve_link:
                            continue
                        
                        cve_id = re.search(r'CVE-\d{4}-\d+', cve_link.get_text()).group(0)
                        
                        # 提取标题和描述
                        title_elem = advisory.find('h3') or advisory.find('h2')
                        title = title_elem.get_text().strip() if title_elem else ""
                        
                        # 提取严重性
                        severity_elem = advisory.find(class_=lambda x: x and 'severity' in x.lower())
                        severity = severity_elem.get_text().strip() if severity_elem else "未知"
                        
                        # 提取链接
                        references = []
                        for link in advisory.find_all('a', href=True):
                            href = link['href']
                            if href.startswith('http'):
                                references.append(href)
                        
                        # 检查是否包含 rustsec - 更严格的检查
                        has_rustsec = False
                        for ref in references:
                            ref_lower = ref.lower()
                            if ('rustsec.org' in ref_lower or 
                                'rustsec' in ref_lower or 
                                '/rustsec/' in ref_lower or
                                'RUSTSEC-' in ref):
                                has_rustsec = True
                                break
                        
                        cve_info = CVEInfo(
                            cve_id=cve_id,
                            title=title,
                            description=title,
                            severity=severity,
                            publish_date="未知",
                            references=references,
                            has_rustsec=has_rustsec,
                            source="GitHub"
                        )
                        
                        cves.append(cve_info)
                        
                    except Exception as e:
                        print(f"解析 GitHub advisory 失败: {e}")
                        continue
                
                print(f"从 GitHub 获取到 {len(cves)} 个 CVE")
                
        except Exception as e:
            print(f"从 GitHub 获取数据失败: {e}")
        
        return cves
    
    def get_sample_rust_cves(self) -> List[CVEInfo]:
        """获取一些已知的 Rust CVE 作为示例数据"""
        print(f"\n生成示例 Rust CVE 数据...")
        
        sample_cves = [
            {
                "cve_id": "CVE-2022-21658",
                "title": "std::fs::remove_dir_all race condition",
                "description": "Race condition in std::fs::remove_dir_all allows deletion of files outside the directory being removed",
                "severity": "High",
                "publish_date": "2022-01-20",
                "references": [
                    "https://blog.rust-lang.org/2022/01/20/cve-2022-21658.html",
                    "https://github.com/rust-lang/rust/issues/93416"
                ],
                "has_rustsec": False
            },
            {
                "cve_id": "CVE-2021-42574",
                "title": "Bidirectional Unicode text can be used to craft source code",
                "description": "Bidirectional Unicode text can be used to craft source code that appears to have different logic",
                "severity": "High", 
                "publish_date": "2021-11-01",
                "references": [
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574",
                    "https://blog.rust-lang.org/2021/11/01/cve-2021-42574.html"
                ],
                "has_rustsec": False
            },
            {
                "cve_id": "CVE-2020-36317", 
                "title": "Use after free in crossbeam-epoch",
                "description": "Use after free vulnerability in crossbeam-epoch crate",
                "severity": "High",
                "publish_date": "2020-12-10",
                "references": [
                    "https://rustsec.org/advisories/RUSTSEC-2020-0111.html",
                    "https://github.com/crossbeam-rs/crossbeam/issues/464"
                ],
                "has_rustsec": True
            },
            {
                "cve_id": "CVE-2019-16760",
                "title": "Cargo prior to 1.26.0 may allow crates to build scripts to overwrite arbitrary files",
                "description": "Cargo build scripts can overwrite arbitrary files on the system",
                "severity": "Critical",
                "publish_date": "2019-09-30", 
                "references": [
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16760",
                    "https://blog.rust-lang.org/2019/09/30/Security-advisory.html"
                ],
                "has_rustsec": False
            }
        ]
        
        cves = []
        for sample in sample_cves:
            cve_info = CVEInfo(
                cve_id=sample["cve_id"],
                title=sample["title"],
                description=sample["description"],
                severity=sample["severity"],
                publish_date=sample["publish_date"],
                references=sample["references"],
                has_rustsec=sample["has_rustsec"],
                source="Sample"
            )
            cves.append(cve_info)
        
        print(f"生成了 {len(cves)} 个示例 CVE")
        return cves
    
    def collect_all_cves(self, use_sample: bool = False) -> List[CVEInfo]:
        """收集所有来源的 CVE"""
        all_cves = []
        
        if use_sample:
            # 使用示例数据
            all_cves.extend(self.get_sample_rust_cves())
        else:
            # 尝试从真实数据源获取
            try:
                nvd_cves = self.get_from_nvd()
                all_cves.extend(nvd_cves)
                time.sleep(self.delay)
            except Exception as e:
                print(f"NVD 数据获取失败: {e}")
            
            # 显示 cve.org 的说明
            try:
                self.get_from_cve_org_note()
            except Exception as e:
                pass
            
            try:
                github_cves = self.get_from_github_advisories()
                all_cves.extend(github_cves)
                time.sleep(self.delay)
            except Exception as e:
                print(f"GitHub 数据获取失败: {e}")
            
            # 如果没有获取到真实数据，使用示例数据
            if not all_cves:
                print("未能获取到真实数据，使用示例数据")
                all_cves.extend(self.get_sample_rust_cves())
        
        # 去重（基于 CVE ID）
        seen_cves = set()
        unique_cves = []
        for cve in all_cves:
            if cve.cve_id not in seen_cves:
                seen_cves.add(cve.cve_id)
                unique_cves.append(cve)
        
        print(f"\n总共收集到 {len(unique_cves)} 个唯一的 CVE")
        return unique_cves


def filter_non_rustsec_cves(all_cves: List[CVEInfo]) -> List[CVEInfo]:
    """筛选出没有 rustsec 引用的 CVE"""
    non_rustsec_cves = [cve for cve in all_cves if not cve.has_rustsec]
    
    print(f"\n筛选结果:")
    print(f"总 CVE 数量: {len(all_cves)}")
    print(f"包含 rustsec 引用: {len(all_cves) - len(non_rustsec_cves)}")
    print(f"不包含 rustsec 引用: {len(non_rustsec_cves)}")
    
    return non_rustsec_cves


def save_results(cves: List[CVEInfo], output_format: str = 'json'):
    """保存筛选结果"""
    if output_format == 'json':
        filename = 'rust_cves_without_rustsec.json'
        data = []
        for cve in cves:
            data.append({
                'cve_id': cve.cve_id,
                'title': cve.title,
                'description': cve.description,
                'severity': cve.severity,
                'publish_date': cve.publish_date,
                'references': cve.references,
                'source': cve.source
            })
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"\nJSON 结果已保存到: {filename}")
    
    elif output_format == 'csv':
        filename = 'rust_cves_without_rustsec.csv'
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['CVE ID', '标题', '描述', '严重性', '发布日期', '引用链接数', '数据源'])
            
            for cve in cves:
                writer.writerow([
                    cve.cve_id,
                    cve.title,
                    cve.description[:200] + '...' if len(cve.description) > 200 else cve.description,
                    cve.severity,
                    cve.publish_date,
                    len(cve.references),
                    cve.source
                ])
        print(f"\nCSV 结果已保存到: {filename}")


def main():
    parser = argparse.ArgumentParser(description='筛选没有 rustsec 引用的 Rust CVE 条目')
    parser.add_argument('--sample', action='store_true', help='使用示例数据而不是真实数据源')
    parser.add_argument('--format', choices=['json', 'csv', 'both'], default='json', help='输出格式')
    parser.add_argument('--delay', type=float, default=2.0, help='请求间隔时间（秒）')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("Rust CVE 筛选工具 - 筛选没有 rustsec 引用的 CVE")
    print("=" * 80)
    
    collector = MultiSourceCVECollector(delay=args.delay)
    
    try:
        # 收集 CVE 数据
        all_cves = collector.collect_all_cves(use_sample=args.sample)
        
        # 筛选没有 rustsec 引用的 CVE
        non_rustsec_cves = filter_non_rustsec_cves(all_cves)
        
        # 显示详细结果
        print(f"\n" + "=" * 80)
        print("没有 rustsec 引用的 CVE 详情:")
        print("=" * 80)
        
        for i, cve in enumerate(non_rustsec_cves, 1):
            print(f"\n{i}. {cve.cve_id}")
            print(f"   标题: {cve.title}")
            print(f"   严重性: {cve.severity}")
            print(f"   发布日期: {cve.publish_date}")
            print(f"   数据源: {cve.source}")
            print(f"   引用数量: {len(cve.references)}")
            if cve.references:
                print(f"   引用链接:")
                for ref in cve.references[:3]:  # 只显示前3个
                    print(f"     - {ref}")
                if len(cve.references) > 3:
                    print(f"     ... 还有 {len(cve.references) - 3} 个引用")
        
        # 保存结果
        if non_rustsec_cves:
            if args.format in ['json', 'both']:
                save_results(non_rustsec_cves, 'json')
            if args.format in ['csv', 'both']:
                save_results(non_rustsec_cves, 'csv')
        else:
            print("\n没有找到符合条件的 CVE")
            
    except KeyboardInterrupt:
        print("\n\n用户中断操作")
    except Exception as e:
        print(f"\n运行出错: {e}")


if __name__ == "__main__":
    main()