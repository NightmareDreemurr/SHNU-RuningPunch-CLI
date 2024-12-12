# Addon.py
# -*- coding: utf-8 -*-

import subprocess
from mitmproxy import http, ctx
import json
import logging

# 配置日志，记录信息、警告和错误
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class Addon:
    def __init__(self):
        self.captured = False

    def response(self, flow: http.HTTPFlow):
        """处理 HTTP 响应，拦截特定 URL 并提取 userId, userName, sex, accountNumber"""
        target_url = "https://cpapp.1lesson.cn/api/user/acquireOpenId"

        # 仅处理目标 URL 的请求
        if flow.request.pretty_url == target_url:
            try:
                # 获取响应并尝试解析 JSON 数据
                response = flow.response
                response_data = response.json()

                # 提取所需字段
                user_id = response_data.get('data', {}).get('userId')
                user_name = response_data.get('data', {}).get('userName')
                sex = response_data.get('data', {}).get('sex')
                account_number = response_data.get('data', {}).get('accountNumber')

                if user_id:

                    # 将其他用户信息写入 userInfo.json，并确保 sex 为整数
                    try:
                        sex_int = int(sex)
                    except (ValueError, TypeError):
                        sex_int = sex  # 保持原样，如果无法转换为整数

                    user_info = {
                        "userId": user_id,
                        "userName": user_name,
                        "sex": sex_int,
                        "accountNumber": account_number
                    }
                    with open("userInfo.json", "w", encoding='utf-8') as file:
                        json.dump(user_info, file, ensure_ascii=False, indent=4)

                    # 打印 user_info 包
                    logging.info(f"捕获到的用户信息: {json.dumps(user_info, ensure_ascii=False, indent=4)}")

                    # 清除系统代理
                    self.clear_system_proxy()

                    # 成功捕获到用户信息后关闭 mitmproxy
                    logging.info("成功捕获到用户信息，正在关闭 mitmproxy。")
                    self.shutdown_mitmproxy()
                else:
                    logging.warning("响应中未找到 userId。")

            except json.JSONDecodeError:
                logging.error("无法解析响应 JSON。")
            except Exception as e:
                logging.error(f"处理响应时出现错误: {e}")

    def clear_system_proxy(self):
        """清除系统代理设置"""
        try:
            subprocess.run([
                "powershell",
                "-Command",
                'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -Name ProxyEnable -Value 0'
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info("系统代理已清除。")
        except subprocess.CalledProcessError as e:
            logging.error(f"清除系统代理失败: {e}")

    def shutdown_mitmproxy(self):
        """停止 mitmproxy"""
        try:
            ctx.master.shutdown()
            logging.info("mitmproxy 已停止。")
        except AttributeError as e:
            logging.error(f"停止 mitmproxy 时出现错误: {e}")


# 启动 mitmproxy 时使用的 Addon 实例
addons = [
    Addon()
]
