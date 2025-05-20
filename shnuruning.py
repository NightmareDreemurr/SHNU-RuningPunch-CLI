# shnuruning.py
# -*- coding: utf-8 -*-
# Original Author: xiaowanggua
# Modified & Optimized by: kcalb_mengwang

import subprocess
import os
from pathlib import Path
import threading
import time
import requests
import logging
import json
from mitmproxy.tools.main import mitmdump
from multiprocessing import Process
import winreg  # 用于检测Windows代理设置
import msvcrt  # 用于检测按键（仅限Windows）
import sys  # 添加 sys 引用用于显示进度条
import socket
import ctypes
import traceback
from datetime import datetime
import logging.handlers
import random  # 添加random模块导入

# 尝试导入 psutil，如果未安装则自动安装
try:
    import psutil
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

def setup_logging():
    """配置日志系统"""
    # 创建logs目录（如果不存在）
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # 生成日志文件名，包含日期
    current_date = datetime.now().strftime("%Y-%m-%d")
    log_file = log_dir / f"shnuruning_{current_date}.log"
    
    # 配置日志格式
    log_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    
    # 配置文件处理器
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(log_format)
    
    # 配置控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_format)
    
    # 获取根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # 清除现有的处理器
    root_logger.handlers.clear()
    
    # 添加处理器
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return root_logger

# 设置日志系统
logger = setup_logging()

def log_exception(e: Exception, context: str = ""):
    """记录异常信息，包括完整的traceback"""
    error_msg = f"{context} - 发生错误: {str(e)}"
    logger.error(error_msg)
    logger.error("详细错误信息:")
    logger.error(traceback.format_exc())

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        log_exception(e, "检查管理员权限时")
        return False

# 如果不是管理员权限则请求管理员权限重新运行脚本
if not is_admin():
    # 提权请求
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
    sys.exit(0)

# 配置日志，记录错误、警告和信息级别的日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 配置 URL
URL_SELECT_STUDENT_SIGN_IN = "https://cpapp.1lesson.cn/api/route/selectStudentSignIn"
URL_INSERT_START_RUNNING = 'https://cpapp.1lesson.cn/api/route/insertStartRunning'
URL_INSERT_FINISH_RUNNING = 'https://cpapp.1lesson.cn/api/route/insertFinishRunning'

# 全局变量
recordId = ''
userids = ''
run_distance = 0
run_times = 0
user_info = {}

# 硬编码的经纬度点
POINTS = [
    {"posLongitude": 121.51818147705078, "posLatitude": 30.837721567871094},
    {"posLongitude": 121.52092847705076, "posLatitude": 30.834883567871294},
    {"posLongitude": 121.51926147705322, "posLatitude": 30.835872567871354},
    {"posLongitude": 121.51749847705033, "posLatitude": 30.835306567871091},
]

def clear_screen():
    """清除命令行屏幕"""
    os.system('cls' if os.name == 'nt' else 'clear')

def kill_proxy_processes():
    """尝试杀死已知的代理进程"""
    known_proxy_processes = {"Clash Verge.exe", "clash.exe", "Clash for Windows.exe"}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] in known_proxy_processes:
                logger.info(f"尝试终止代理进程: {proc.info['name']} (PID: {proc.info['pid']})")
                proc_obj = psutil.Process(proc.info['pid'])
                proc_obj.terminate()  # 尝试优雅终止进程
                try:
                    proc_obj.wait(timeout=3)  # 等待进程结束
                    logger.info(f"已终止进程: {proc.info['name']} (PID: {proc.info['pid']})")
                except psutil.TimeoutExpired:
                    logger.warning(f"进程 {proc.info['name']} 未能在3秒内结束，尝试强制结束。")
                    proc_obj.kill()  # 强制结束
                    logger.info(f"已强制结束进程: {proc.info['name']} (PID: {proc.info['pid']})")
        except Exception as e:
            log_exception(e, f"处理进程 {proc.info.get('name', 'unknown')} 时")

def is_proxy_enabled():
    """检测系统代理是否已启用"""
    try:
        registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
        key = winreg.OpenKey(registry, r"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        proxy_enable, regtype = winreg.QueryValueEx(key, "ProxyEnable")
        proxy_server, regtype = winreg.QueryValueEx(key, "ProxyServer")
        if proxy_enable == 1:
            logger.info(f"系统代理已启用，代理服务器: {proxy_server}")
            return True
    except Exception as e:
        log_exception(e, "检测系统代理设置时")

    # 检查环境变量中的代理设置
    http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
    socks_proxy = os.environ.get('SOCKS_PROXY') or os.environ.get('socks_proxy')
    if http_proxy or https_proxy or socks_proxy:
        logger.info(f"环境变量中检测到代理设置: HTTP_PROXY={http_proxy}, HTTPS_PROXY={https_proxy}, SOCKS_PROXY={socks_proxy}")
        return True

    # 检查已知代理进程
    known_proxy_processes = {"Clash Verge.exe", "clash.exe", "Clash for Windows.exe"}
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] in known_proxy_processes:
                logger.info(f"检测到代理进程运行: {proc.info['name']}")
                return True
        except Exception as e:
            log_exception(e, f"检查进程 {proc.info.get('name', 'unknown')} 时")

    # 检查特定端口是否在监听
    proxy_ports = [7890, 7891, 7892, 7893]
    for port in proxy_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    logger.info(f"检测到端口 {port} 正在监听，可能是代理服务器。")
                    return True
        except Exception as e:
            log_exception(e, f"检查端口 {port} 时")
    return False

def is_certificate_installed():
    """检查 mitmproxy CA 证书是否已安装到当前用户的受信任的根存储区"""
    try:
        result = subprocess.run(["certutil", "-user", "-store", "Root"], capture_output=True, text=True, check=True)
        if "mitmproxy" in result.stdout.lower():
            logger.info("mitmproxy CA 证书已安装到当前用户的受信任的根存储区。")
            return True
        else:
            logger.warning("mitmproxy CA 证书未安装到当前用户的受信任的根存储区。")
            return False
    except subprocess.CalledProcessError as e:
        logger.error(f"检查证书安装状态时出错: {e}")
        return False

def post(url, data, headers=None, max_retries=3, retry_delay=2):
    """发送 POST 请求并处理响应
    
    Args:
        url: 请求URL
        data: 请求数据
        headers: 请求头
        max_retries: 最大重试次数
        retry_delay: 重试间隔（秒）
    """
    retry_count = 0
    last_error = None
    
    while retry_count < max_retries:
        try:
            # 设置请求超时
            response = requests.post(
                url, 
                data=data, 
                headers=headers,
                timeout=10,  # 设置10秒超时
                verify=True  # 启用SSL验证
            )
            response.raise_for_status()
            json_data = response.json()
            logger.info(f"POST {url} 响应: {json_data}")
            return json_data
            
        except requests.exceptions.SSLError as e:
            last_error = e
            logger.warning(f"SSL错误 (尝试 {retry_count + 1}/{max_retries}): {str(e)}")
            if "EOF occurred in violation of protocol" in str(e):
                logger.info("检测到SSL连接意外终止，可能是网络问题或服务器问题")
            elif "certificate verify failed" in str(e):
                logger.error("SSL证书验证失败，请检查证书是否正确安装")
                break  # 证书问题不重试
                
        except requests.exceptions.ConnectionError as e:
            last_error = e
            logger.warning(f"连接错误 (尝试 {retry_count + 1}/{max_retries}): {str(e)}")
            
        except requests.exceptions.Timeout as e:
            last_error = e
            logger.warning(f"请求超时 (尝试 {retry_count + 1}/{max_retries}): {str(e)}")
            
        except requests.exceptions.RequestException as e:
            last_error = e
            logger.warning(f"请求错误 (尝试 {retry_count + 1}/{max_retries}): {str(e)}")
            
        except Exception as e:
            last_error = e
            logger.error(f"未知错误: {str(e)}")
            break  # 未知错误不重试
            
        retry_count += 1
        if retry_count < max_retries:
            logger.info(f"等待 {retry_delay} 秒后重试...")
            time.sleep(retry_delay)
    
    # 所有重试都失败后
    error_msg = f"POST请求到 {url} 失败，已重试 {retry_count} 次"
    if last_error:
        error_msg += f"，最后错误: {str(last_error)}"
    logger.error(error_msg)
    
    # 根据错误类型给出具体建议
    if isinstance(last_error, requests.exceptions.SSLError):
        logger.error("SSL错误，请检查：")
        logger.error("1. 网络连接是否稳定")
        logger.error("2. 是否已正确安装mitmproxy证书")
        logger.error("3. 是否关闭了其他代理软件")
    elif isinstance(last_error, requests.exceptions.ConnectionError):
        logger.error("连接错误，请检查：")
        logger.error("1. 网络连接是否正常")
        logger.error("2. 服务器是否可访问")
        logger.error("3. 防火墙设置是否正确")
    
    return None

def runs(point):
    """模拟跑步位置点上报"""
    if point < 0 or point >= len(POINTS):
        logger.error("无效的位置点索引")
        return
    points = {
        "userId": userids,
        "recordId": recordId,
        "posLongitude": POINTS[point]["posLongitude"],
        "posLatitude": POINTS[point]["posLatitude"],
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    logger.info(f"发送位置点: {points}")
    post(URL_SELECT_STUDENT_SIGN_IN, points, headers=headers)

def is_mitmproxy_installed():
    """检查 mitmproxy 是否已安装"""
    try:
        # 首先检查是否安装了 mitmproxy 包
        result = subprocess.run([sys.executable, "-c", "import mitmproxy"], 
                                capture_output=True, 
                                text=True, 
                                check=False)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def install_mitmproxy():
    """安装 mitmproxy"""
    print("正在安装 mitmproxy，请稍等...")
    logger.info("开始安装 mitmproxy")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "mitmproxy"])
        print("mitmproxy 安装成功")
        logger.info("mitmproxy 安装成功")
        return True
    except subprocess.CalledProcessError as e:
        print(f"mitmproxy 安装失败: {e}")
        logger.error(f"mitmproxy 安装失败: {e}")
        return False

def install_certificate():
    """安装 mitmproxy CA 证书"""
    # 检查 mitmproxy 是否已安装
    if not is_mitmproxy_installed():
        print("未检测到 mitmproxy，尝试安装...")
        if not install_mitmproxy():
            print("mitmproxy 安装失败，无法生成证书")
            logger.error("mitmproxy 安装失败，无法生成证书")
            return False

    # 使用老版本的证书路径，这对应于 mitmproxy 的标准路径
    ca_cert_path = Path(os.path.expanduser("~/.mitmproxy/mitmproxy-ca.p12"))
    ca_cert_p12_path = Path(os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.p12"))
    
    logger.info(f"检查证书路径: {ca_cert_path} 和 {ca_cert_p12_path}")

    # 检查证书是否存在（检查两个可能的路径）
    if not ca_cert_path.exists() and not ca_cert_p12_path.exists():
        print("无法找到 mitmproxy CA 证书，将启动mitmproxy并引导您手动安装证书。")
        logger.info("CA 证书不存在，引导用户手动安装...")

        
        
        # 先杀死可能的代理进程
        kill_proxy_processes()
        
        print("正在启动mitmproxy服务...")
        # 使用多进程而不是线程来运行mitmproxy
        try:
            # 利用已有的多进程函数运行mitmproxy
            p = Process(target=start_mitmproxy, name='mitmproxy')
            p.start()
            logger.info("mitmproxy进程已启动")
            
            # 等待mitmproxy启动
            time.sleep(2)
            
            # 重要：设置系统代理，确保浏览器流量通过mitmproxy
            try:
                subprocess.run(
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f',
                    shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ /d 127.0.0.1:8080 /f',
                    shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("系统代理已设置为 127.0.0.1:8080")
                print("系统代理已设置为 127.0.0.1:8080")
            except subprocess.CalledProcessError as e:
                logger.error(f"设置系统代理失败: {e}")
                print(f"设置系统代理失败: {e}")
            
            try:
                
                
                
                
                # 打开浏览器引导用户安装证书
                cert_url = "http://mitm.it/"
                print(f"正在打开浏览器，请访问 {cert_url} 并按照提示安装证书...")
                logger.info(f"引导用户访问 {cert_url} 安装证书")
                # 尝试使用默认浏览器打开证书安装页面
                import webbrowser
                webbrowser.open(cert_url)
                
                # 清除系统代理
                try:
                    subprocess.run(
                        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f',
                        shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logger.info("系统代理已清除")
                    print("系统代理已清除")
                except subprocess.CalledProcessError as e:
                    logger.error(f"清除系统代理失败: {e}")
                    print(f"清除系统代理失败: {e}")

                # 终止mitmproxy进程
                if p.is_alive():
                    p.terminate()
                    p.join()
                    logger.info("mitmproxy进程已终止")
                
                # 检查证书是否已安装
                if is_certificate_installed():
                    print("恭喜！mitmproxy CA 证书已成功安装。")
                    logger.info("证书已成功安装。")
                    return True
                else:
                    print("mitmproxy CA 证书未能成功安装，请再次尝试或手动安装。")
                    logger.warning("证书未能成功安装。")
                    return False
                    
            except Exception as e:
                print(f"打开浏览器失败: {e}")
                logger.error(f"打开浏览器引导用户安装证书失败: {e}")
                print("请手动打开浏览器，访问 http://mitm.it/ 并按照提示安装证书。")
                
                # 确保在出现异常时也终止mitmproxy进程和清除代理
                try:
                    subprocess.run(
                        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f',
                        shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    pass
                    
                if p.is_alive():
                    p.terminate()
                    p.join()
                    logger.info("异常情况下mitmproxy进程已终止")
                
                input("证书安装完成后，请按回车键继续...")
                return False
                
        except Exception as e:
            print(f"启动mitmproxy服务失败: {e}")
            logger.error(f"启动mitmproxy服务失败: {e}")
            return False

    # 如果证书已存在，检查是否已安装
    if is_certificate_installed():
        print("mitmproxy CA 证书已正确安装。")
        return True
    else:
        print("检测到证书文件存在，但未安装到系统中。")
        print("请手动安装证书或使用浏览器访问 http://mitm.it/ 安装。")
        
        # 尝试打开浏览器引导用户安装
        try:

            clear_screen()
            print("\n请按照以下步骤安装证书:")
            print("1. 在打开的网页中，点击对应您操作系统的图标下载证书（Get mitmproxy-ca-cert.p12）")
            print("2. 双击下载的证书文件，按照系统提示安装")
            print("3. 在证书安装向导中，一路继续安装，最後按是")
            print("4. 完成安装后，关闭浏览器并返回此程序")
            
            print("\n按下回车后，将为您关闭当前代理，并打开mitm.it，请按照提示安装证书。")
            input("\n阅读完成后，请按回车键继续...")
            
            
            # 先杀死可能的代理进程
            kill_proxy_processes()
            
            # 使用多进程运行mitmproxy
            p = Process(target=start_mitmproxy, name='mitmproxy')
            p.start()
            logger.info("mitmproxy进程已启动（用于现有证书安装）")
            
            time.sleep(2)  # 等待mitmproxy启动
            
            # 设置系统代理
            try:
                subprocess.run(
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f',
                    shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ /d 127.0.0.1:8080 /f',
                    shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("系统代理已设置为 127.0.0.1:8080")
                print("系统代理已设置为 127.0.0.1:8080")
            except subprocess.CalledProcessError as e:
                logger.error(f"设置系统代理失败: {e}")
                print(f"设置系统代理失败: {e}")
            
            import webbrowser
            webbrowser.open("http://mitm.it/") 
            print("\n正在等待证书安装完成...")
            print("请在浏览器中完成证书安装，然后返回此窗口按回车键继续...")
            
            # 每隔5秒清屏并重复显示提示，防止被日志淹没
            waiting_start = time.time()
            while True:
                time.sleep(5)
                clear_screen()
                print("\n" + "="*50)
                print("请在浏览器中完成证书安装")
                print("完成后请返回此窗口，按回车键继续...")
                print("="*50)
                
                # 检查是否有键盘输入
                if msvcrt.kbhit():
                    # 清空缓冲区
                    key = msvcrt.getch()
                    if key == b'\r':  # 回车键
                        break
                    
                # 如果等待超过2分钟，再次询问
                if time.time() - waiting_start > 120:
                    choice = input("\n您似乎花了较长时间，是否已完成证书安装？(y/n): ").lower()
                    if choice == 'y':
                        break
                    waiting_start = time.time()  # 重置计时器
            
            # 清屏再显示一次确认信息
            clear_screen()
            print("\n证书安装已完成，继续程序...\n")
            
            # 清除系统代理
            try:
                subprocess.run(
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f',
                    shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("系统代理已清除")
                print("系统代理已清除")
            except subprocess.CalledProcessError as e:
                logger.error(f"清除系统代理失败: {e}")
                print(f"清除系统代理失败: {e}")
            
            # 终止mitmproxy进程
            if p.is_alive():
                p.terminate()
                p.join()
                logger.info("mitmproxy进程已终止")
        except Exception as e:
            logger.error(f"打开浏览器引导用户安装证书失败: {e}")
            # 确保进程被终止和代理被清除
            try:
                subprocess.run(
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f',
                    shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
                
            try:
                if 'p' in locals() and p.is_alive():
                    p.terminate()
                    p.join()
            except:
                pass
        
        # 再次检查证书是否已安装
        if is_certificate_installed():
            print("证书已成功安装。")
            return True
        else:
            print("证书安装失败，请手动检查。")
            logger.error("证书安装失败，请手动检查。")
            return False

def start_mitmproxy():
    """启动 mitmproxy"""
    mitmdump(['-q', '-s', "./Addon.py"])

def run_mitmproxy() -> Process:
    """运行 mitmproxy 的多进程"""
    p = Process(target=start_mitmproxy, name='mitmproxy')
    p.start()
    logger.info("mitmproxy 进程已启动。")
    return p

def stop_mitmproxy(p: Process) -> None:
    """停止 mitmproxy 的多进程"""
    if p.is_alive():
        p.terminate()
        p.join()
        logger.info("mitmproxy 进程已终止。")

def start_getting_user_id():
    """开始获取用户 ID 的流程"""
    print("开始获取用户 ID，请按照提示操作。")
    try:
        subprocess.run(
            'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f',
            shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ /d 127.0.0.1:8080 /f',
            shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("系统代理已设置为 127.0.0.1:8080。")
    except subprocess.CalledProcessError as e:
        print(f"设置系统代理失败: {e}")
        logger.error(f"设置系统代理失败: {e}")
        return None

    p = run_mitmproxy()
    return p

def stop_mitmproxy_and_proxy(p: Process):
    """停止 mitmproxy 并清除系统代理"""
    stop_mitmproxy(p)
    try:
        subprocess.run(
            'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f',
            shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("系统代理已清除。")
    except subprocess.CalledProcessError as e:
        print(f"清除系统代理失败: {e}")
        logger.error(f"清除系统代理失败: {e}")

def clear_system_proxy():
    """清除系统代理设置"""
    try:
        subprocess.run([
            "powershell",
            "-Command",
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -Name ProxyEnable -Value 0'
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info("系统代理已清除。")
    except subprocess.CalledProcessError as e:
        logger.error(f"清除系统代理失败: {e}")

def display_progress_bar(progress, total, bar_length=50):
    """显示进度条"""
    percent = float(progress) / total
    arrow = '-' * int(round(percent * bar_length) - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    sys.stdout.write(f"\r[{arrow}{spaces}] 已跑步：{int(round(percent * 100))}%")
    sys.stdout.flush()

def countdown_with_progress_bar(total_seconds):
    """使用进度条显示跑步进度，并允许用户按'N'结束跑步"""
    global run_distance, run_times, user_info

    start_time = time.time()
    end_time = start_time + total_seconds
    cancelled = False

    while True:
        current_time = time.time()
        elapsed = current_time - start_time

        if elapsed >= total_seconds:
            break

        progress = elapsed
        progress_percent = progress / total_seconds
        if progress_percent > 1:
            progress_percent = 1

        clear_screen()
        print(f"姓名：{user_info.get('userName', '未知')}")
        print(f"性别：{'男' if user_info.get('sex') == 1 else '女' if user_info.get('sex') == 0 else '未知'}")
        print(f"学号：{user_info.get('accountNumber', '未知')}")
        print(f"userId：{userids}")
        print(f"[进度条] 已跑步：{int(round(progress_percent * 100))}%")
        print("按'N'结束跑步并取消。")

        display_progress_bar(elapsed, total_seconds)

        if msvcrt.kbhit():
            key = msvcrt.getch()
            if key in [b'N', b'n']:
                cancelled = True
                break

        time.sleep(1)

    if cancelled:
        print("\n跑步已被用户取消。")
        finish(cancelled=True)
    else:
        print("\n倒计时结束。")
        finish()

def finish(cancelled=False):
    """跑步结束，上报结束信息"""
    if cancelled:
        print("跑步已取消，上报取消信息。")
    else:
        runs(3)
        data = {
            "userId": userids,
            "runningRecordId": recordId,
            "mileage": run_distance,
            "speedAllocation": 0,
            "totalTime": int(run_times / 60),
            "data": []
        }
        logger.info(f"上报结束数据: {data}")
        r = post(URL_INSERT_FINISH_RUNNING, data=json.dumps(data), headers={'Content-Type': 'application/json'})
        if r:
            print("\n跑步结束，已上报成功。请打开小程序检查是否次数增加。")
        else:
            print("\n跑步结束，上报失败。")


def start_countdown():
    global run_distance, run_times, recordId, userids, user_info
    try:
        run_time = int(input("请输入时间（分钟）（不超过25）："))
        if run_time > 25 or run_time <= 0:
            print("时间输入不合法，请输入1到25之间的整数。")
            time.sleep(2)
            clear_screen()
            start_countdown()
            return
        run_times = run_time * 60
        run_distance = int(input("请输入距离（公里）（不小于2）："))
        if run_distance < 2:
            print("距离输入不合法，请输入不小于2的整数。")
            time.sleep(2)
            clear_screen()
            start_countdown()
            return
    except ValueError:
        print("输入错误，请输入有效的整数。")
        time.sleep(2)
        clear_screen()
        start_countdown()
        return

    # 选择跑步模式
    clear_screen()
    print("\n===== 跑步模式选择 =====")
    print("\n您可以选择以下跑步模式：")
    print("1. 模拟真实跑步（等待倒计时结束后上报）")
    print("2. 快速完成（立即上报完成结果）")
    print("\n⚠️ 警告：选择快速完成模式可能会被后台系统检测到异常行为，")
    print("   可能导致本次跑步记录被清除或账号被标记。请自行承担风险。")

    run_mode = '0'
    while run_mode not in ['1', '2']:
        run_mode = input("\n请选择模式 (1/2): ").strip()
        if run_mode not in ['1', '2']:
            print("输入无效，请输入1或2。")

    # 如果选择快速完成模式，询问次数
    run_count = 1
    if run_mode == '2':
        try:
            run_count_input = input("\n请输入连续跑步次数 (默认为1): ").strip()
            if run_count_input:
                run_count = int(run_count_input)
                if run_count <= 0:
                    print("次数必须为正整数，设置为默认值1。")
                    run_count = 1
                elif run_count > 10:
                    confirmation = input("⚠️ 警告：设置较高次数可能增加检测风险。确定继续吗？(y/n): ").lower()
                    if confirmation != 'y':
                        print("已取消，设置为默认值1。")
                        run_count = 1
        except ValueError:
            print("输入无效，使用默认值1。")
            run_count = 1

    # 执行跑步逻辑
    for current_run in range(1, run_count + 1):
        if run_count > 1:
            clear_screen()
            print(f"\n===== 正在执行第 {current_run}/{run_count} 次跑步 =====")

        # 获取runningRecord
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        r = post(URL_INSERT_START_RUNNING, {'userId': userids}, headers=headers)
        if r and 'data' in r and 'runningRecord' in r['data']:
            recordId = r["data"]["runningRecord"]
            logger.info(f"取得 recordId: {recordId}")
        else:
            print("无法取得 runningRecord。")
            if current_run > 1:
                print(f"已完成 {current_run - 1}/{run_count} 次跑步。")
            time.sleep(2)
            clear_screen()
            return

        # 发送初始位置点
        runs(0)
        time.sleep(1)
        runs(1)
        time.sleep(1)
        runs(2)

        # 根据选择的模式进行操作
        if run_mode == '1':
            # 正常倒计时模式
            print(f"\n倒计时开始: {run_time * 60} 秒")
            countdown_with_progress_bar(run_time * 60)
            # 只跑一次，不需要循环
            break
        else:  # run_mode == '2'
            # 快速完成模式
            print("\n您选择了快速完成模式，正在上报跑步结束...")
            logger.info("用户选择快速完成模式，跳过倒计时")
            time.sleep(2)  # 稍微等待一下，让用户能看到提示
            finish()  # 直接调用完成函数

            # 如果不是最后一次跑步，等待一个随机时间再开始下一次
            if current_run < run_count:
                wait_time = random.randint(5, 15)  # 5-15秒随机等待
                print(f"\n等待 {wait_time} 秒后开始下一次跑步...")
                for i in range(wait_time, 0, -1):
                    print(f"下一次跑步将在 {i} 秒后开始...", end='\r')
                    time.sleep(1)
                print(" " * 50, end='\r')  # 清除倒计时行

    if run_mode == '2' and run_count > 1:
        print(f"\n✅ 已成功完成 {run_count} 次跑步！")
        input("\n按回车键返回主菜单...")
        clear_screen()
        display_interface1()
def check_user_id_and_show_run_screen():
    global userids, user_info
    if os.path.exists("userInfo.json") and os.path.getsize("userInfo.json") > 0:
        try:
            with open("userInfo.json", 'r', encoding='utf-8') as file:
                content = file.read()
                # 检查是否是旧格式（单用户）
                if content.strip().startswith('{'):
                    # 旧格式，转换为列表
                    users = [json.loads(content)]
                else:
                    # 新格式（多用户数组）
                    users = json.loads(content)
                logger.info(f"读取到 {len(users)} 个用户信息")
            
            if not users:
                print("未找到有效的用户信息，请先获取用户ID。")
                time.sleep(2)
                clear_screen()
                display_interface1()
                return
            
            # 如果只有一个用户，直接使用该用户
            if len(users) == 1:
                user_info = users[0]
                userids = user_info.get('userId', '')
                show_user_info_and_run()
                return
            
            # 显示用户选择菜单
            while True:
                clear_screen()
                print("请选择要使用的用户：")
                for i, user in enumerate(users):
                    user_name = user.get('userName', '未知')
                    account_number = user.get('accountNumber', '未知')
                    sex = user.get('sex')
                    gender = "男" if sex == 1 else "女" if sex == 0 else "未知"
                    print(f"{i+1}. {user_name} ({account_number}) - {gender}")
                
                print("\n0. 返回主菜单")
                
                choice = input("\n请输入序号选择用户: ").strip()
                if choice == '0':
                    clear_screen()
                    display_interface1()
                    return
                
                try:
                    choice_idx = int(choice) - 1
                    if 0 <= choice_idx < len(users):
                        user_info = users[choice_idx]
                        userids = user_info.get('userId', '')
                        show_user_info_and_run()
                        return
                    else:
                        print("无效的选择，请重新输入。")
                        time.sleep(1)
                except ValueError:
                    print("请输入有效的数字。")
                    time.sleep(1)
            
        except FileNotFoundError:
            logger.error("userInfo.json 未找到。")
            print("文件错误: userInfo.json 未找到。")
            time.sleep(2)
            clear_screen()
            display_interface1()
        except json.JSONDecodeError as e:
            logger.error(f"解析 userInfo.json 时出错: {e}")
            print(f"文件错误: 解析 userInfo.json 时出错: {e}")
            time.sleep(2)
            clear_screen()
            display_interface1()
        except IOError as e:
            logger.error(f"读取文件时出错: {e}")
            print(f"文件错误: 读取文件时出错: {e}")
            time.sleep(2)
            clear_screen()
            display_interface1()
    else:
        print("未找到用户信息文件，请先获取用户ID。")
        time.sleep(2)
        clear_screen()
        display_interface1()

def show_user_info_and_run():
    """显示选中的用户信息并开始跑步"""
    global userids, user_info
    
    clear_screen()
    print("用户信息如下：")
    print(f"用户ID: {userids}")
    print(f"姓名: {user_info.get('userName', '未知')}")
    sex = user_info.get('sex')
    if isinstance(sex, str):
        sex = sex.strip()
        try:
            sex = int(sex)
        except ValueError:
            pass
    gender = "男" if sex == 1 else "女" if sex == 0 else "未知"
    print(f"性别: {gender}")
    print(f"学号: {user_info.get('accountNumber', '未知')}")

    print("\n请按照以下提示进行跑步设置。")
    print("注意：每天第一次跑步前请在小程序内点击'开始跑步'，然后直接点击结束跑步，再使用本程序跑步。")
    print("请填写合理的时间和距离，以确保点击开始后和结束后各代理一段时间增减。")
    print("如果使用中程序关闭，请手动点击结束再使用本程序。")
    start_countdown()

def display_interface1():
    if not (os.path.exists("userInfo.json") and os.path.getsize("userInfo.json") > 0):
        print("您没有用户ID或用户信息, 自动跳转到获取用户ID的界面。")
        time.sleep(2)
        get_user_id_flow()
        return

    clear_screen()
    print("\n本程序仅供学习和研究使用。使用本程序进行学校体锻打卡自动代打可能违反学校的规定和政策。")
    print("用户在使用本程序前应充分了解并遵守相关规定和法律法规。")
    print("开发者不对任何因使用本程序而产生的后果负责，包括但不限于学术处罚、法律责任或其他任何形式的损失。")
    print("用户需自行承担使用本程序所带来的所有风险和责任。")
    print("请勿将本程序用于任何非法或不道德的用途。")
    print("[1] 开始跑步")
    print("[2] 重新获取用户ID")

    while True:
        choice = input("请输入选项（1或2）：").strip()
        if choice == '1':
            handle_start_running()
            break
        elif choice == '2':
            handle_reacquire_userid()
            break
        else:
            print("输入无效，请输入1或2。")

def handle_start_running():
    if not (os.path.exists("userInfo.json") and os.path.getsize("userInfo.json") > 0):
        print("您没有用户ID或用户信息，请先获取。")
        time.sleep(2)
        clear_screen()
        display_interface1()
        return
    check_user_id_and_show_run_screen()

def handle_reacquire_userid():
    print("重新获取userId将覆盖现有的userInfo.json文件。")
    confirm = input("确认要重新获取用户ID吗？（Y/N）：").strip().upper()
    if confirm == 'Y':
        get_user_id_flow()
    elif confirm == 'N':
        display_interface1()
    else:
        print("输入无效，请输入Y或N。")
        handle_reacquire_userid()

def get_user_id_flow():
    clear_screen()
    print("\n!!!请注意!!!")
    print("抓取用户ID之前请关闭所有VPN/梯子/代理服务")
    print("开始获取用户ID后，所有代理会被清除！如有需要请事后手动重新打开！")
    choice = input("是否开始获取用户ID？（Y/N）：").strip().upper()
    if choice == 'Y':
        # 尝试清除系统代理
        print("尝试清除系统代理...")
        clear_system_proxy()
        time.sleep(1)  # 等待1秒

        # 检测是否还有代理启用
        if is_proxy_enabled():
            print("检测到系统代理仍然开启，尝试结束已知代理进程...")
            kill_proxy_processes()
            clear_system_proxy()
            time.sleep(1)
            if is_proxy_enabled():
                print("\n检测到系统代理已开启，请手动关闭所有VPN/梯子/代理服务后再尝试获取用户ID。")
                print("请关闭代理后，重新运行程序。")
                logger.warning("用户尝试获取userID时代理仍已开启。")
                input("按任意键返回主界面...")
                display_interface1()
                return

        p = start_getting_user_id()
        if p is None:
            return
        clear_screen()
        print("\n请打开电脑微信-小程序-体锻打卡小程序。")
        print("如果已打开小程序，请重新打开。")
        print("若打开后没反应，请过几秒重新打开。")
        
        # 设置最大等待时间（秒）
        max_wait_time = 60
        start_time = time.time()
        
        try:
            while True:
                if (os.path.exists("userInfo.json") and os.path.getsize("userInfo.json") > 0):
                    try:
                        with open("userInfo.json", 'r', encoding='utf-8') as file:
                            content = file.read()
                            # 检查是否是旧格式（单用户）
                            if content.strip().startswith('{'):
                                # 旧格式
                                user_info_local = json.loads(content)
                            else:
                                # 新格式（多用户数组）
                                users = json.loads(content)
                                # 使用最后一个用户（最新添加的）
                                user_info_local = users[-1] if users else {}
                    except json.JSONDecodeError as e:
                        logger.error(f"解析 userInfo.json 时出错: {e}")
                        print(f"解析用户信息文件出错: {e}")
                        time.sleep(2)
                        stop_mitmproxy_and_proxy(p)
                        display_interface1()
                        return
                    
                    # 确保安全停止 mitmproxy 进程
                    try:
                        stop_mitmproxy_and_proxy(p)
                        logger.info("成功停止 mitmproxy 进程和代理")
                    except Exception as e:
                        logger.error(f"停止 mitmproxy 时出错: {e}")
                        print(f"警告: 停止后台进程时出错，可能需要手动清理。错误: {e}")
                        time.sleep(2)
                    
                    user_id = user_info_local.get('userId', '未知')
                    user_name = user_info_local.get('userName', '未知')
                    sex = user_info_local.get('sex', '未知')
                    account_number = user_info_local.get('accountNumber', '未知')
                    gender = "男" if sex == 1 else "女" if sex == 0 else "未知"
                    
                    clear_screen()
                    print("\n已抓取到用户ID及信息：")
                    print(f"已抓取到用户ID: {user_id}")
                    print(f"姓名为: {user_name}")
                    print(f"性别为: {gender}")
                    print(f"学号为: {account_number}")
                    
                    run_choice = input("是否开始跑步？（Y/N）：").strip().upper()
                    if run_choice == 'Y':
                        # 不再需要停止 mitmproxy，因为已经在上面停止了
                        start_countdown()
                        return
                    elif run_choice == 'N':
                        # 不再需要停止 mitmproxy，因为已经在上面停止了
                        print("\n是否重新获取用户ID？")
                        retry = input("（Y）是，重新获取用户ID；（N）否，返回开始界面：").strip().upper()
                        if retry == 'Y':
                            get_user_id_flow()
                            return
                        elif retry == 'N':
                            display_interface1()
                            return
                        else:
                            print("输入无效，返回主界面。")
                            time.sleep(1)
                            display_interface1()
                            return
                    else:
                        print("输入无效，返回主界面。")
                        time.sleep(1)
                        display_interface1()
                        return
                
                # 检查是否超时
                elapsed_time = time.time() - start_time
                if elapsed_time > max_wait_time:
                    print("\n等待超时，未能成功获取用户ID。")
                    logger.warning("获取用户ID超时")
                    try:
                        stop_mitmproxy_and_proxy(p)
                    except Exception as e:
                        logger.error(f"超时后停止 mitmproxy 时出错: {e}")
                    
                    retry = input("是否重试？(Y/N): ").strip().upper()
                    if retry == 'Y':
                        get_user_id_flow()
                        return
                    else:
                        display_interface1()
                        return
                
                # 显示等待信息和剩余时间
                remaining = max_wait_time - int(elapsed_time)
                print(f"等待用户ID抓取中，请确保微信小程序已正确操作... (剩余{remaining}秒)  ", end='\r')
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"获取用户ID过程中发生错误: {e}")
            print(f"\n出现错误: {e}")
            try:
                stop_mitmproxy_and_proxy(p)
            except:
                pass
            time.sleep(2)
            display_interface1()
            return
            
    elif choice == 'N':
        display_interface1()
    else:
        print("输入无效，请输入Y或N。")
        time.sleep(1)
        get_user_id_flow()

def main():
    try:
        logger.info("程序启动")
        if not is_certificate_installed():
            print("检测到未安装 mitmproxy CA 证书，开始安装。")
            success = install_certificate()
            if not success:
                print("证书安装失败，请手动检查。")
                logger.error("证书安装失败，请手动检查。")
                time.sleep(2)
        else:
            print("mitmproxy CA 证书已安装。")
            logger.info("mitmproxy CA 证书已安装")
        time.sleep(2)

        if not (os.path.exists("userInfo.json") and os.path.getsize("userInfo.json") > 0):
            clear_screen()
            print("\n您没有用户ID或用户信息, 是否要开始获取? 缺失userId无法进行跑步。")
            choice = input("是否开始获取用户ID？（Y/N）：").strip().upper()
            if choice == 'Y':
                get_user_id_flow()
            elif choice == 'N':
                pass
            else:
                print("输入无效，请输入Y或N。")
                main()

        display_interface1()
    except Exception as e:
        log_exception(e, "程序主函数执行时")
        print(f"程序发生错误: {str(e)}")
        print("请查看logs目录下的日志文件了解详细信息。")
        input("按回车键退出...")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        logger.info("程序被用户中断")
        sys.exit(0)
    except Exception as e:
        log_exception(e, "程序启动时")
        print(f"程序发生严重错误: {str(e)}")
        print("请查看logs目录下的日志文件了解详细信息。")
        input("按回车键退出...")
        sys.exit(1)
