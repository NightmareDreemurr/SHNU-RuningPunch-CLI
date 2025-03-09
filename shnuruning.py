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

# 尝试导入 psutil，如果未安装则自动安装
try:
    import psutil
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
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
                logging.info(f"尝试终止代理进程: {proc.info['name']} (PID: {proc.info['pid']})")
                proc_obj = psutil.Process(proc.info['pid'])
                proc_obj.terminate()  # 尝试优雅终止进程
                try:
                    proc_obj.wait(timeout=3)  # 等待进程结束
                    logging.info(f"已终止进程: {proc.info['name']} (PID: {proc.info['pid']})")
                except psutil.TimeoutExpired:
                    logging.warning(f"进程 {proc.info['name']} 未能在3秒内结束，尝试强制结束。")
                    proc_obj.kill()  # 强制结束
                    logging.info(f"已强制结束进程: {proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

def is_proxy_enabled():
    """检测系统代理是否已启用"""
    try:
        registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
        key = winreg.OpenKey(registry, r"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        proxy_enable, regtype = winreg.QueryValueEx(key, "ProxyEnable")
        proxy_server, regtype = winreg.QueryValueEx(key, "ProxyServer")
        if proxy_enable == 1:
            logging.info(f"系统代理已启用，代理服务器: {proxy_server}")
            return True
    except Exception as e:
        logging.error(f"检测系统代理设置时出错: {e}")

    # 检查环境变量中的代理设置
    http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
    https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
    socks_proxy = os.environ.get('SOCKS_PROXY') or os.environ.get('socks_proxy')
    if http_proxy or https_proxy or socks_proxy:
        logging.info(f"环境变量中检测到代理设置: HTTP_PROXY={http_proxy}, HTTPS_PROXY={https_proxy}, SOCKS_PROXY={socks_proxy}")
        return True

    # 检查已知代理进程
    known_proxy_processes = {"Clash Verge.exe", "clash.exe", "Clash for Windows.exe"}
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] in known_proxy_processes:
                logging.info(f"检测到代理进程运行: {proc.info['name']}")
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # 检查特定端口是否在监听
    proxy_ports = [
        7890, 7891, 7892, 7893
    ]

    for port in proxy_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                logging.info(f"检测到端口 {port} 正在监听，可能是代理服务器。")
                return True
    return False

def is_certificate_installed():
    """检查 mitmproxy CA 证书是否已安装到当前用户的受信任的根存储区"""
    try:
        result = subprocess.run(["certutil", "-user", "-store", "Root"], capture_output=True, text=True, check=True)
        if "mitmproxy" in result.stdout.lower():
            logging.info("mitmproxy CA 证书已安装到当前用户的受信任的根存储区。")
            return True
        else:
            logging.warning("mitmproxy CA 证书未安装到当前用户的受信任的根存储区。")
            return False
    except subprocess.CalledProcessError as e:
        logging.error(f"检查证书安装状态时出错: {e}")
        return False

def post(url, data, headers=None):
    """发送 POST 请求并处理响应"""
    try:
        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()
        json_data = response.json()
        logging.info(f"POST {url} 响应: {json_data}")
        return json_data
    except requests.exceptions.RequestException as e:
        logging.error(f"POST 请求失败: {e}")
        return None

def runs(point):
    """模拟跑步位置点上报"""
    if point < 0 or point >= len(POINTS):
        logging.error("无效的位置点索引")
        return
    points = {
        "userId": userids,
        "recordId": recordId,
        "posLongitude": POINTS[point]["posLongitude"],
        "posLatitude": POINTS[point]["posLatitude"],
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    logging.info(f"发送位置点: {points}")
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
    logging.info("开始安装 mitmproxy")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "mitmproxy"])
        print("mitmproxy 安装成功")
        logging.info("mitmproxy 安装成功")
        return True
    except subprocess.CalledProcessError as e:
        print(f"mitmproxy 安装失败: {e}")
        logging.error(f"mitmproxy 安装失败: {e}")
        return False

def install_certificate():
    """安装 mitmproxy CA 证书"""
    # 检查 mitmproxy 是否已安装
    if not is_mitmproxy_installed():
        print("未检测到 mitmproxy，尝试安装...")
        if not install_mitmproxy():
            print("mitmproxy 安装失败，无法生成证书")
            logging.error("mitmproxy 安装失败，无法生成证书")
            return False

    # 使用老版本的证书路径，这对应于 mitmproxy 的标准路径
    ca_cert_path = Path(os.path.expanduser("~/.mitmproxy/mitmproxy-ca.p12"))
    ca_cert_p12_path = Path(os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.p12"))
    ca_cert_pem_path = Path(os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem"))
    
    logging.info(f"检查证书路径: {ca_cert_path} 和 {ca_cert_p12_path}")

    # 检查证书是否存在（检查两个可能的路径）
    if not ca_cert_path.exists() and not ca_cert_p12_path.exists():
        print("无法找到 mitmproxy CA 证书，开始生成证书，约限 5 秒。")
        logging.info("CA 证书不存在，生成中...")

        def generate_certificate():
            try:
                # 使用 Python 模块方式直接运行 mitmproxy，避免路径问题
                subprocess.run([sys.executable, "-m", "mitmproxy.tools.main"], 
                              check=True, 
                              stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL)
            except Exception as e:
                logging.error(f"生成证书时发生错误: {e}")

        thread = threading.Thread(target=generate_certificate)
        thread.start()
        time.sleep(5)
        
        # 终止 mitmproxy 进程
        try:
            # 搜索和终止所有相关进程
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if 'python' in proc_name:
                        proc_obj = psutil.Process(proc.info['pid'])
                        cmdline = " ".join(proc_obj.cmdline()).lower()
                        if 'mitmproxy' in cmdline:
                            proc_obj.terminate()
                            logging.info(f"终止了进程: {proc.info['pid']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # 再尝试使用传统方法
            subprocess.run(["taskkill", "/F", "/IM", "mitmdump.exe"], 
                          check=False, 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL)
            logging.info("已终止 mitmproxy 进程")
        except Exception as e:
            logging.error(f"终止 mitmproxy 进程时出错: {e}")

        # 再次检查证书是否生成
        if not ca_cert_path.exists() and not ca_cert_p12_path.exists():
            print("证书生成失败，无法找到 mitmproxy CA 证书。")
            logging.error("证书生成失败")
            return False

    # 确定实际存在的证书路径
    cert_to_install = ca_cert_p12_path if ca_cert_p12_path.exists() else ca_cert_path
    logging.info(f"将安装证书: {cert_to_install}")

    # 安装证书
    try:
        subprocess.run([
            "powershell",
            "-Command",
            f'Import-PfxCertificate -FilePath "{cert_to_install}" -CertStoreLocation "Cert:\\CurrentUser\\Root"'
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("证书安装成功。")
        logging.info("证书已成功安装。")
    except subprocess.CalledProcessError as e:
        print(f"证书安装失败: {e}")
        logging.error(f"证书安装失败: {e}")
        return False

    if is_certificate_installed():
        print("mitmproxy CA 证书已正确安装。")
        return True
    else:
        print("mitmproxy CA 证书未能成功安装。")
        return False

def start_mitmproxy():
    """启动 mitmproxy"""
    mitmdump(['-q', '-s', "./Addon.py"])

def run_mitmproxy() -> Process:
    """运行 mitmproxy 的多进程"""
    p = Process(target=start_mitmproxy, name='mitmproxy')
    p.start()
    logging.info("mitmproxy 进程已启动。")
    return p

def stop_mitmproxy(p: Process) -> None:
    """停止 mitmproxy 的多进程"""
    if p.is_alive():
        p.terminate()
        p.join()
        logging.info("mitmproxy 进程已终止。")

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
        logging.info("系统代理已设置为 127.0.0.1:8080。")
    except subprocess.CalledProcessError as e:
        print(f"设置系统代理失败: {e}")
        logging.error(f"设置系统代理失败: {e}")
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
        logging.info("系统代理已清除。")
    except subprocess.CalledProcessError as e:
        print(f"清除系统代理失败: {e}")
        logging.error(f"清除系统代理失败: {e}")

def clear_system_proxy():
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
        logging.info(f"上报结束数据: {data}")
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

    # 获取runningRecord
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = post(URL_INSERT_START_RUNNING, {'userId': userids}, headers=headers)
    if r and 'data' in r and 'runningRecord' in r['data']:
        recordId = r["data"]["runningRecord"]
        logging.info(f"取得 recordId: {recordId}")
    else:
        print("无法取得 runningRecord。")
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
    else:  # run_mode == '2'
        # 快速完成模式
        print("\n您选择了快速完成模式，正在上报跑步结束...")
        logging.info("用户选择快速完成模式，跳过倒计时")
        time.sleep(2)  # 稍微等待一下，让用户能看到提示
        finish()  # 直接调用完成函数

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
                logging.info(f"读取到 {len(users)} 个用户信息")
            
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
            logging.error("userInfo.json 未找到。")
            print("文件错误: userInfo.json 未找到。")
            time.sleep(2)
            clear_screen()
            display_interface1()
        except json.JSONDecodeError as e:
            logging.error(f"解析 userInfo.json 时出错: {e}")
            print(f"文件错误: 解析 userInfo.json 时出错: {e}")
            time.sleep(2)
            clear_screen()
            display_interface1()
        except IOError as e:
            logging.error(f"读取文件时出错: {e}")
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
                logging.warning("用户尝试获取userID时代理仍已开启。")
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
                        logging.error(f"解析 userInfo.json 时出错: {e}")
                        print(f"解析用户信息文件出错: {e}")
                        time.sleep(2)
                        stop_mitmproxy_and_proxy(p)
                        display_interface1()
                        return
                    
                    # 确保安全停止 mitmproxy 进程
                    try:
                        stop_mitmproxy_and_proxy(p)
                        logging.info("成功停止 mitmproxy 进程和代理")
                    except Exception as e:
                        logging.error(f"停止 mitmproxy 时出错: {e}")
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
                    logging.warning("获取用户ID超时")
                    try:
                        stop_mitmproxy_and_proxy(p)
                    except Exception as e:
                        logging.error(f"超时后停止 mitmproxy 时出错: {e}")
                    
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
            logging.error(f"获取用户ID过程中发生错误: {e}")
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
    if not is_certificate_installed():
        print("检测到未安装 mitmproxy CA 证书，开始安装。")
        success = install_certificate()
        if not success:
            print("证书安装失败，请手动检查。")
            logging.error("证书安装失败，请手动检查。")
            time.sleep(2)
    else:
        print("mitmproxy CA 证书已安装。")
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


if __name__ == '__main__':
    main()
