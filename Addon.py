# Addon.py
# -*- coding: utf-8 -*-

import subprocess
from mitmproxy import http, ctx
import json
import logging
import os

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
                    
                    # 检查是否存在现有用户信息
                    users = []
                    try:
                        if os.path.exists("userInfo.json") and os.path.getsize("userInfo.json") > 0:
                            with open("userInfo.json", "r", encoding='utf-8') as file:
                                content = file.read()
                                # 检查是否是旧格式（单用户）
                                if content.strip().startswith('{'):
                                    # 旧格式
                                    old_user = json.loads(content)
                                    users = [old_user]
                                else:
                                    # 新格式（多用户数组）
                                    users = json.loads(content)
                    except Exception as e:
                        print(f"读取用户信息时出错: {e}")
                        # 如果有错误，从新开始
                        users = []
                    
                    # 检查用户是否已存在
                    user_exists = False
                    for i, existing_user in enumerate(users):
                        if existing_user.get('userId') == user_id:
                            users[i] = user_info  # 更新现有用户
                            user_exists = True
                            break
                    
                    if not user_exists:
                        users.append(user_info)  # 添加新用户
                    
                    with open("userInfo.json", "w", encoding='utf-8') as file:
                        json.dump(users, file, ensure_ascii=False, indent=4)
                    
                    print(f"用户信息已保存: {user_name}({account_number})")
                    
                    # 打印 user_info 包
                    logging.info(f"捕获到的用户信息: {json.dumps(user_info, ensure_ascii=False, indent=4)}")

                    # 清除系统代理
                    self.clear_system_proxy()

                    # 通知已成功捕获用户信息，但不关闭mitmproxy
                    logging.info("成功捕获到用户信息，等待主程序关闭mitmproxy。")

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
