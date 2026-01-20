"""规则更新API测试用例 (使用 requests)"""

import requests
import json
import time
from typing import Optional, Dict, Any

BASE_URL = "http://localhost:8000/api/v1"


class RuleUpdateTestCase:
    """规则更新测试用例"""

    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()

    def request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """发送HTTP请求"""
        url = f"{self.base_url}{path}"
        print(f"\n{'='*60}")
        print(f"[{method.upper()}] {url}")

        if kwargs.get('json'):
            print(f"Request Body: {json.dumps(kwargs['json'], indent=2, ensure_ascii=False)}")

        try:
            resp = self.session.request(method, url, timeout=30, **kwargs)
            status = resp.status_code
            try:
                data = resp.json()
            except:
                data = resp.text

            print(f"Status: {status}")
            if isinstance(data, dict):
                print(f"Response: {json.dumps(data, indent=2, ensure_ascii=False)[:1500]}")
            else:
                print(f"Response: {str(data)[:500]}")

            return {"status": status, "data": data}
        except requests.exceptions.ConnectionError as e:
            print(f"连接失败: {e}")
            return {"status": 0, "data": {"error": "连接失败"}}
        except Exception as e:
            print(f"请求异常: {e}")
            return {"status": 0, "data": {"error": str(e)}}

    def test_1_check_initial_state(self):
        """测试1: 检查初始状态"""
        print("\n" + "="*60)
        print("测试1: 检查初始状态")
        print("="*60)

        # 检查规则列表
        result = self.request("GET", "/rules?limit=5")
        if result['status'] == 0:
            print("✗ 无法连接到服务器")
            return 0, 0
        rules_count = result['data'].get('total', 0)
        print(f"✓ 当前规则数: {rules_count}")

        # 检查版本列表
        result = self.request("GET", "/rules/versions?limit=5")
        versions = result['data'].get('versions', [])
        print(f"✓ 当前版本数: {len(versions)}")

        for v in versions[:3]:
            print(f"  - {v.get('version')}: rule_count={v.get('rule_count')}, is_active={v.get('is_active')}")

        return rules_count, len(versions)

    def test_2_trigger_download(self):
        """测试2: 触发规则下载"""
        print("\n" + "="*60)
        print("测试2: 触发规则下载")
        print("="*60)

        result = self.request("POST", "/rules/download", json={"force": True})

        if result['status'] == 200:
            task_id = result['data'].get('task_id')
            print(f"✓ 下载任务已启动: {task_id}")
            return task_id
        else:
            print(f"✗ 下载启动失败: {result['data']}")
            return None

    def test_3_wait_download_complete(self, max_wait: int = 120):
        """测试3: 等待下载完成"""
        print("\n" + "="*60)
        print("测试3: 等待下载完成")
        print("="*60)

        start_time = time.time()
        while time.time() - start_time < max_wait:
            result = self.request("GET", "/rules/download/status")

            if result['status'] == 200:
                status = result['data'].get('status')
                progress = result['data'].get('progress', 0)
                print(f"  状态: {status}, 进度: {progress}%")

                if status == 'ready':
                    print(f"✓ 下载完成!")
                    return True
                elif status == 'failed':
                    print(f"✗ 下载失败: {result['data'].get('error')}")
                    return False

            time.sleep(2)

        print(f"✗ 下载超时")
        return False

    def test_4_get_preview(self):
        """测试4: 获取变更预览"""
        print("\n" + "="*60)
        print("测试4: 获取变更预览")
        print("="*60)

        result = self.request("GET", "/rules/preview")

        if result['status'] == 200:
            data = result['data']
            summary = data.get('summary', {})
            print(f"✓ 预览获取成功:")
            print(f"  - 新增规则: {summary.get('added_count', 0)}")
            print(f"  - 修改规则: {summary.get('modified_count', 0)}")
            print(f"  - 删除规则: {summary.get('deleted_count', 0)}")
            print(f"  - 未变更: {summary.get('unchanged_count', 0)}")
            print(f"  - added_total: {data.get('added_total', 0)}")
            print(f"  - modified_total: {data.get('modified_total', 0)}")
            return data
        else:
            print(f"✗ 预览获取失败: {result['data']}")
            return None

    def test_5_confirm_update(self):
        """测试5: 确认更新"""
        print("\n" + "="*60)
        print("测试5: 确认更新")
        print("="*60)

        result = self.request("POST", "/rules/update", json={
            "apply_changes": True,
            "description": "API测试自动更新"
        })

        if result['status'] == 200:
            data = result['data']
            print(f"✓ 更新成功:")
            print(f"  - 版本: {data.get('version')}")
            print(f"  - 规则数: {data.get('rule_count')}")
            print(f"  - 新增: {data.get('added_count')}")
            print(f"  - 修改: {data.get('modified_count')}")
            print(f"  - 删除: {data.get('deleted_count')}")
            return data
        else:
            print(f"✗ 更新失败: {result['data']}")
            return None

    def test_6_verify_rules(self):
        """测试6: 验证规则列表"""
        print("\n" + "="*60)
        print("测试6: 验证规则列表")
        print("="*60)

        result = self.request("GET", "/rules?limit=10")

        if result['status'] == 200:
            data = result['data']
            total = data.get('total', 0)
            rules = data.get('rules', [])
            print(f"✓ 规则列表获取成功:")
            print(f"  - 总规则数: {total}")
            print(f"  - 返回规则数: {len(rules)}")

            if rules:
                print(f"  前3条规则:")
                for r in rules[:3]:
                    print(f"    - SID {r.get('sid')}: {r.get('msg', '')[:50]}")
            else:
                print(f"  ✗ 规则列表为空!")

            return total, rules
        else:
            print(f"✗ 获取规则列表失败: {result['data']}")
            return 0, []

    def test_7_verify_versions(self):
        """测试7: 验证版本历史"""
        print("\n" + "="*60)
        print("测试7: 验证版本历史")
        print("="*60)

        result = self.request("GET", "/rules/versions?limit=10")

        if result['status'] == 200:
            data = result['data']
            versions = data.get('versions', [])
            print(f"✓ 版本列表获取成功:")
            print(f"  - 版本数: {len(versions)}")

            for v in versions[:5]:
                active = "✓" if v.get('is_active') else " "
                print(f"  [{active}] {v.get('version')}: rule_count={v.get('rule_count')}")

            return versions
        else:
            print(f"✗ 获取版本列表失败: {result['data']}")
            return []

    def test_8_check_database(self):
        """测试8: 检查数据库状态"""
        print("\n" + "="*60)
        print("测试8: 检查数据库状态 (通过分类统计)")
        print("="*60)

        result = self.request("GET", "/rules/categories")

        if result['status'] == 200:
            data = result['data']
            classtype = data.get('classtype', [])
            msg_prefix = data.get('msg_prefix', [])
            print(f"✓ 分类统计获取成功:")
            print(f"  - classtype 分类数: {len(classtype)}")
            print(f"  - msg_prefix 分类数: {len(msg_prefix)}")

            total_rules = sum(c.get('rule_count', 0) for c in classtype)
            print(f"  - 按 classtype 统计总规则数: {total_rules}")

            if classtype:
                print(f"  前5个 classtype:")
                for c in classtype[:5]:
                    print(f"    - {c.get('category_name')}: {c.get('rule_count')}条")

            return data
        else:
            print(f"✗ 获取分类统计失败: {result['data']}")
            return None


def run_full_test():
    """运行完整测试流程"""
    print("\n" + "="*60)
    print("规则更新API完整测试")
    print("="*60)

    test = RuleUpdateTestCase()

    # 1. 检查初始状态
    initial_rules, initial_versions = test.test_1_check_initial_state()

    # 2. 触发下载
    task_id = test.test_2_trigger_download()
    if not task_id:
        print("\n✗ 测试终止: 无法启动下载")
        return False

    # 3. 等待下载完成
    download_ok = test.test_3_wait_download_complete()
    if not download_ok:
        print("\n✗ 测试终止: 下载失败")
        return False

    # 4. 获取预览
    preview = test.test_4_get_preview()
    if not preview:
        print("\n✗ 测试终止: 无法获取预览")
        return False

    # 5. 确认更新
    update_result = test.test_5_confirm_update()
    if not update_result:
        print("\n✗ 测试终止: 更新失败")
        return False

    # 6. 验证规则列表
    total_rules, rules = test.test_6_verify_rules()

    # 7. 验证版本历史
    versions = test.test_7_verify_versions()

    # 8. 检查数据库状态
    test.test_8_check_database()

    # 总结
    print("\n" + "="*60)
    print("测试总结")
    print("="*60)
    print(f"初始规则数: {initial_rules}")
    print(f"更新后规则数: {total_rules}")
    print(f"版本数: {len(versions)}")

    if total_rules > 0:
        print("\n✓✓✓ 测试通过: 规则已成功入库 ✓✓✓")
        return True
    else:
        print("\n✗✗✗ 测试失败: 规则列表仍然为空 ✗✗✗")
        return False


def run_quick_check():
    """快速检查当前状态"""
    print("\n" + "="*60)
    print("快速状态检查")
    print("="*60)

    test = RuleUpdateTestCase()
    test.test_1_check_initial_state()
    test.test_6_verify_rules()
    test.test_7_verify_versions()
    test.test_8_check_database()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "check":
        run_quick_check()
    else:
        run_full_test()
