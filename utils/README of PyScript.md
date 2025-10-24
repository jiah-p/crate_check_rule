# Rust CVE 筛选工具使用说明

## 概述

本项目提供了多种方式来获取和筛选 Rust 相关的 CVE（通用漏洞披露）数据，主要目的是找出**没有 RustSec 引用**的 CVE 条目。

## 可用脚本

### 1. rust_cve_filter.py（推荐）
**主要特点：**
- 使用 NVD API v2 获取权威 CVE 数据
- 自动筛选出没有 RustSec 引用的 CVE
- 支持 JSON 和 CSV 输出格式
- 可靠性高，数据质量好

**使用方法：**
```bash
# 基本使用
python3 rust_cve_filter.py --format json

# 使用示例数据测试
python3 rust_cve_filter.py --sample --format json

# 调整请求间隔
python3 rust_cve_filter.py --delay 3.0 --format both
```

**输出文件：** `rust_cves_without_rustsec.json`

### 2. filter_no_rustsec_cve.py
**主要特点：**
- 原始版本，尝试直接从 cve.org 网站爬取数据
- 由于 cve.org 使用 JavaScript 动态加载，实际效果有限
- 包含更详细的页面解析逻辑

**使用方法：**
```bash
python3 filter_no_rustsec_cve.py --format json --max-pages 5
```

### 3. cve_org_selenium_scraper.py
**主要特点：**
- 使用 Selenium 浏览器自动化来处理 JavaScript 内容
- 能够真正从 cve.org 获取数据
- 需要安装额外依赖

**依赖安装：**
```bash
pip install selenium
# 还需要下载 ChromeDriver
```

**使用方法：**
```bash
# 无头模式运行
python3 cve_org_selenium_scraper.py --keyword rust --max-results 20

# 显示浏览器窗口（调试用）
python3 cve_org_selenium_scraper.py --show-browser --max-results 10
```

## 数据源说明

### NVD API (推荐)
- **优点：** 官方权威数据源，稳定可靠，包含完整的 CVE 元数据
- **缺点：** 可能有请求频率限制
- **数据质量：** 高

### cve.org 网站
- **优点：** 官方 CVE 数据库
- **缺点：** 使用 JavaScript 动态加载，爬取困难
- **建议：** 使用 Selenium 版本

### GitHub Security Advisories
- **优点：** 包含额外的安全建议
- **缺点：** 数据相对较少
- **状态：** 已集成到主脚本中

## RustSec 检测逻辑

脚本使用以下模式来检测 CVE 是否包含 RustSec 引用：

1. **URL 引用检查：**
   - `rustsec.org` - 官方域名
   - `rustsec` - 通用引用  
   - `/rustsec/` - 路径引用
   - `RUSTSEC-` - 标识符引用

2. **描述内容检查：**
   - 在 CVE 描述中查找 RustSec 相关内容

## 最新筛选结果

**最近一次运行结果：**
- 总 CVE 数量: 200
- 包含 RustSec 引用: 182
- **不包含 RustSec 引用: 18**

**部分没有 RustSec 引用的 CVE：**
- CVE-2018-1000622 (rustdoc)
- CVE-2019-12083 (Rust Standard Library)
- CVE-2020-26297 (mdBook)
- CVE-2021-21269 (Keymaker)
- 等等...

## 故障排除

### 常见问题

1. **网络连接问题**
   ```
   解决方案：检查网络连接，或调整 --delay 参数增加请求间隔
   ```

2. **Selenium 相关错误**
   ```
   解决方案：
   - 安装 selenium: pip install selenium
   - 下载对应的浏览器驱动程序
   - 确保驱动程序在 PATH 中
   ```

3. **NVD API 限制**
   ```
   解决方案：增加 --delay 参数值，或使用示例数据模式 --sample
   ```

### 调试技巧

1. **使用示例数据测试**
   ```bash
   python3 rust_cve_filter.py --sample
   ```

2. **查看详细输出**
   - 脚本会实时显示处理进度
   - 检查 "包含 rustsec 引用" 的计数是否合理

3. **验证结果**
   ```bash
   # 检查输出文件
   cat rust_cves_without_rustsec.json | jq '.[] | .cve_id'
   
   # 验证特定 CVE 不在结果中
   grep "CVE-2017-1000430" rust_cves_without_rustsec.json
   ```

## 贡献

如果发现以下情况，欢迎报告：
- 错误的筛选结果（包含 RustSec 但被归类为没有）
- 新的 RustSec 引用模式
- 性能优化建议

---

**注意：** 由于 CVE 数据库持续更新，建议定期重新运行脚本获取最新数据。