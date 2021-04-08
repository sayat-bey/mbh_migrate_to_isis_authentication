import yaml
import time
import queue
import re
import ipaddress
from threading import Thread
from pprint import pformat
from getpass import getpass
from sys import argv
from datetime import datetime
from pathlib import Path
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, SSHException

# решение проблемы при подключении к IOS XR
import logging
logging.getLogger('paramiko.transport').disabled = True 


#######################################################################################
# ------------------------------ classes part ----------------------------------------#
#######################################################################################


class CellSiteGateway:
    def __init__(self, ip, host):
        self.hostname = host
        self.ip_address = ip
        self.ssh_conn = None
        self.os_type = "cisco_ios"

        self.connection_status = True  # failed connection status, False if connection fails
        self.connection_error_msg = ""  # connection error message

        self.isis_interface = []
        self.commands = []
        self.configuration_log = []

    def configure(self, cmd_list):
        self.configuration_log.append(self.ssh_conn.send_config_set(cmd_list))

    def commit(self):
        try:
            self.configuration_log.append(self.ssh_conn.save_config())
        except Exception as err_msg:
            self.configuration_log.append(f"COMMIT is OK after msg:{err_msg}")
            self.configuration_log.append(self.ssh_conn.send_command("\n", expect_string=r"#"))

    def reset(self):
        self.connection_status = True  # failed connection status, False if connection fails
        self.connection_error_msg = ""  # connection error message
        self.isis_interface = []
        self.commands = []
        self.configuration_log = []


class PaggXR(CellSiteGateway):
    def __init__(self, ip, host):
        CellSiteGateway.__init__(self, ip, host)
        self.os_type = "cisco_xr"

    def commit(self):
        self.configuration_log.append(self.ssh_conn.commit())
        self.ssh_conn.exit_config_mode()

    def configure(self, cmd):
        self.ssh_conn.send_config_set(cmd)
        self.configuration_log.append(self.ssh_conn.send_command("show configuration"))

    def reset(self):
        self.connection_status = True  # failed connection status, False if connection fails
        self.connection_error_msg = ""  # connection error message
        self.isis_interface = []
        self.commands = []
        self.configuration_log = []


class PaggXE(CellSiteGateway):
    def __init__(self, ip, host):
        CellSiteGateway.__init__(self, ip, host)
        self.os_type = "cisco_xe"

    def configure(self, cmd_list):
        self.configuration_log.append(self.ssh_conn.send_config_set(cmd_list))

    def commit(self):
        self.configuration_log.append(self.ssh_conn.save_config())

    def reset(self):
        self.connection_status = True  # failed connection status, False if connection fails
        self.connection_error_msg = ""  # connection error message
        self.isis_interface = []
        self.commands = []
        self.configuration_log = []
        

#######################################################################################
# ------------------------------ def function part -----------------------------------#
#######################################################################################


def get_argv(arguments):
    settings = {
        "maxth": 20,
        "send-only": False,
        "key-chain": False,
        "no-send-only": False,
        "conf": False
    }
    mt_pattern = re.compile(r"mt([0-9]+)")
    for arg in arguments:
        if "mt" in arg:
            match = re.search(mt_pattern, arg)
            if match and int(match[1]) <= 100:
                settings["maxth"] = int(match[1])
        elif arg == "send":
            settings["send-only"] = True
        elif arg == "key":
            settings["key-chain"] = True
        elif arg == "nosend":
            settings["no-send-only"] = True
        elif arg == "cfg" or arg == "CFG" or arg == "conf":
            settings["conf"] = True

    if settings["send-only"] is False \
            and settings["key-chain"] is False \
            and settings["no-send-only"] is False \
            and settings["conf"] is False:

        print("\nsettings from file is loaded\n")
        with open("steps.yaml") as file_input:
            settings_from_file = yaml.load(file_input, yaml.SafeLoader)
            current_step = settings_from_file[-1]
            current_settings = settings_from_file[current_step]
            settings.update(current_settings)

        with open("steps.yaml", "w") as file_output:
            if current_step == len(settings_from_file) - 2:
                settings_from_file[-1] = 0
            else:
                settings_from_file[-1] = current_step + 1
            yaml.dump(settings_from_file, file_output)

    print(
          f"max threads:...................{settings['maxth']}\n"
          f"config mode:...................{settings['conf']}\n"
          f"set send-only:.................{settings['send-only']}\n"
          f"set key-chain:.................{settings['key-chain']}\n"
          f"set no-send-only:..............{settings['no-send-only']}\n"
          )
    return settings


def get_user_pw():
    user = input("Enter login: ")
    psw = getpass()
    return user, psw


def get_devinfo(yaml_file):
    devs = []
    with open(yaml_file, "r") as file:
        devices_info = yaml.load(file, yaml.SafeLoader)
        
        for ios, devlist in devices_info.items():
            if ios == "xr":
                for hostname, ip_address in devlist.items():
                    dev = PaggXR(ip=ip_address, host=hostname)
                    devs.append(dev)
            elif ios == "xe":
                for hostname, ip_address in devlist.items():
                    dev = PaggXE(ip=ip_address, host=hostname)
                    devs.append(dev)
            elif ios == "ios":
                for hostname, ip_address in devlist.items():
                    dev = CellSiteGateway(ip=ip_address, host=hostname)
                    devs.append(dev)
            else:
                print("ERROR IOS")

    print()
    return devs


def write_logs(devices, current_time, log_folder, settings):
    failed_conn_count = 0

    conn_msg_filename = log_folder / f"{current_time}_connection_error_msg.txt"
    conn_msg_filename_file = open(conn_msg_filename, "w")
    device_info_filename = log_folder / f"{current_time}_device_info.txt"
    device_info_filename_file = open(device_info_filename, "w")
    config_filename = log_folder / f"{current_time}_configuration_log.txt"
    config_filename_file = open(config_filename, "w")
    commands_filename = log_folder / f"{current_time}_configuration_commands.txt"
    commands_filename_file = open(commands_filename, "w")

    for device in devices:
        if device.connection_status:
            export_device_info(device, device_info_filename_file, settings)  # export deviceice info: show, status, etc
        else:
            failed_conn_count += 1
            conn_msg_filename_file.write("-" * 80 + "\n")
            conn_msg_filename_file.write(f"### {device.hostname} : {device.ip_address} ###\n\n")
            conn_msg_filename_file.write(f"{device.connection_error_msg}\n")
            config_filename_file.write("\n\n")
            
        if settings["conf"] and device.commands:
            config_filename_file.write("#" * 80 + "\n")
            config_filename_file.write(f"### {device.hostname} : {device.ip_address} ###\n\n")
            config_filename_file.write("".join(device.configuration_log))
            config_filename_file.write("\n\n")

        if device.commands:
            commands_filename_file.write(f"### {device.hostname} : {device.ip_address}\n\n")
            commands_filename_file.write("\n".join(device.commands))
            commands_filename_file.write("\n\n\n")

    conn_msg_filename_file.close()
    device_info_filename_file.close()
    config_filename_file.close()
    commands_filename_file.close()

    if not settings["conf"]:
        config_filename.unlink()
    if all([d.connection_status is True for d in devices]):
        conn_msg_filename.unlink()

    return failed_conn_count


#######################################################################################
# ------------------------------ get bs port -----------------------------------------#
#######################################################################################


def export_device_info(device, export_file, settings):
    export_file.write("#" * 80 + "\n")
    export_file.write(f"### {device.hostname} : {device.ip_address} ###\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("settings\n\n")
    export_file.write(pformat(settings))
    export_file.write("\n\n")
    
    export_file.write("-" * 80 + "\n")
    export_file.write("device.isis_interface\n\n")
    export_file.write(" ".join(device.isis_interface))
    export_file.write("\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.commands\n\n")
    export_file.write("\n".join(device.commands))
    export_file.write("\n\n")
    

def check_key_chain(device):
    
    log = device.ssh_conn.send_command("show key chain ISIS-HELLO")
    if "ALA" in log:   # проверка что вывод есть
        if device.os_type == "cisco_ios" or device.os_type == "cisco_xe":         
            if "ISIS-HELLO" not in log:
                device.commands.append("key chain ISIS-HELLO")
                device.commands.append("key 1")
                device.commands.append("key-string 7 04500A3C2A395C1E5B4852")

        elif device.os_type == "cisco_xr":
            if "ISIS-HELLO" not in log:
                device.commands.append("key chain ISIS-HELLO")
                device.commands.append("key 1")
                device.commands.append("accept-lifetime 00:00:00 march 13 2015 infinite")
                device.commands.append("key-string password 141C1331291C3A7B767964")
                device.commands.append("send-lifetime 00:00:00 march 13 2015 infinite")
                device.commands.append("cryptographic-algorithm HMAC-MD5")
            
            log_group = device.ssh_conn.send_command("show running-config group ISIS_L2_IF")
            if "ALA" in log_group:
                if "ISIS-HELLO" not in log_group:
                    print(f"{device.hostname:39}[ATTENTION] ISIS_L2_IF is added to config list")
                    device.commands.append("group ISIS_L2_IF")
                    device.commands.append("router isis '.*'")
                    device.commands.append("interface 'Gi.*'")
                    device.commands.append("circuit-type level-2-only")
                    device.commands.append("point-to-point")
                    device.commands.append("hello-interval 3")
                    device.commands.append("hello-password keychain ISIS-HELLO")
                    device.commands.append("hello-multiplier 20")
                    device.commands.append("address-family ipv4 unicast")
                    device.commands.append("interface 'Te.*'")
                    device.commands.append("circuit-type level-2-only")
                    device.commands.append("point-to-point")
                    device.commands.append("hello-interval 3")
                    device.commands.append("hello-password keychain ISIS-HELLO")
                    device.commands.append("hello-multiplier 20")
                    device.commands.append("address-family ipv4 unicast")
                    device.commands.append("interface 'Bundle-Ether.*'")
                    device.commands.append("circuit-type level-2-only")
                    device.commands.append("point-to-point")
                    device.commands.append("hello-interval 3")
                    device.commands.append("hello-password keychain ISIS-HELLO")
                    device.commands.append("hello-multiplier 20")
                    device.commands.append("address-family ipv4 unicast")
                    device.commands.append("end-group")
            else:
                print(f"{device.hostname:39}[ERROR] show ISIS_L2_IF - empty")    
    else:
        print(f"{device.hostname:39}[ERROR] show key chain - empty")
            

def define_isis_interface(device):
    
    log = device.ssh_conn.send_command("show isis neighbors")
    if "ALA" in log:
        if device.os_type == "cisco_ios" or device.os_type == "cisco_xe":
            for line in log.splitlines():
                match = re.search(r".*L2 +(\S+\d+) +10\.238\..* +UP", line)     # akta-0401-pag L2 (Vl200) 10.238.121.65
                if match:
                    device.isis_interface.append(match[1])

        elif device.os_type == "cisco_xr":
            for line in log.splitlines():
                match = re.search(r"\S+ +(\S+) +\*PtoP\* +Up +\d+ +L2 +Capable", line)
                if match:
                    device.isis_interface.append(match[1])

        if device.os_type == "cisco_ios":
            check_p2p_in_acl(device, log)

    else:
        print(f"{device.hostname:39}[ERROR] show isis neighbor - empty")


def check_p2p_in_acl(device, log):
    log_acl = device.ssh_conn.send_command("show ip access-lists MGMT")
    for line in log.splitlines():
        match = re.search(r".*L2 +\S+\d+ +(10\.238\.\d+\.\d+) +UP", line)
        if match:
            ipv4 = ipaddress.ip_address(match[1])
            ipv3 = ipv4 - 1
            if not any([str(ipv4) in log_acl, str(ipv3) in log_acl]):
                print(f"{device.hostname:39}[ERROR] {str(ipv4)} {str(ipv3)} not in acl mgmt")
            else:
                print(f"{device.hostname:39}test {str(ipv4)} {str(ipv3)} in acl mgmt")


def phase1_send_only(device):
    
    if device.os_type == "cisco_ios" or device.os_type == "cisco_xe":
        for inf in device.isis_interface:
            log = device.ssh_conn.send_command(f"show running-config interface {inf}")
            if "ALA" in log:
                if "key-chain ISIS-HELLO" not in log and "mode md5" not in log:
                    device.commands.append(f"interface {inf}")
                    device.commands.append("isis authentication send-only")
            else:
                print(f"{device.hostname:39}[ERROR] show run inf {inf} - empty")
     
    elif device.os_type == "cisco_xr":
        for inf in device.isis_interface:
            log = device.ssh_conn.send_command(f"show running-config router isis access interface {inf} inheritance")
            if "ALA" in log:
                if "keychain ISIS-HELLO" not in log:
                    device.commands.append(f"router isis access interface {inf}")
                    device.commands.append("hello-password keychain ISIS-HELLO send-only")
            else:
                print(f"{device.hostname:39}[ERROR] show run inf {inf} - empty")
                
                
def phase2_authentication_mode(device):
    
    if device.os_type == "cisco_ios" or device.os_type == "cisco_xe":
        for inf in device.isis_interface:
            log = device.ssh_conn.send_command(f"show running-config interface {inf}")
            if "ALA" in log:
                if "send-only" in log:
                    device.commands.append(f"interface {inf}")
                    device.commands.append("isis authentication mode md5")
                    device.commands.append("isis authentication key-chain ISIS-HELLO")
            else:
                print(f"{device.hostname:39}[ERROR] show run inf {inf} - empty")
     
    elif device.os_type == "cisco_xr":
        for inf in device.isis_interface:
            log = device.ssh_conn.send_command(f"show running-config router isis access interface {inf} inheritance")
            if "ALA" in log:
                if "send-only" in log:
                    device.commands.append(f"router isis access interface {inf}")
                    device.commands.append("apply-group ISIS_L2_IF")
            else:
                print(f"{device.hostname:39}[ERROR] show run inf {inf} - empty")
 

def phase3_authentication_mode(device): 

    if device.os_type == "cisco_ios" or device.os_type == "cisco_xe":
        for inf in device.isis_interface:
            log = device.ssh_conn.send_command(f"show running-config interface {inf}")
            if "ALA" in log:
                if "send-only" in log:
                    device.commands.append(f"interface {inf}")
                    device.commands.append("no isis authentication send-only")
            else:
                print(f"{device.hostname:39}[ERROR] show run inf {inf} - empty")
     
    elif device.os_type == "cisco_xr":
        for inf in device.isis_interface:
            log = device.ssh_conn.send_command(f"show running-config router isis access interface {inf}")
            if "ALA" in log:
                if "send-only" in log:
                    device.commands.append(f"router isis access interface {inf}")
                    device.commands.append("no hello-password keychain ISIS-HELLO send-only")

                    exclude = ["router isis access", "interface", "apply-group", "!", "ALA"]
                    for line in log.splitlines():
                        if not any([i in line for i in exclude]):
                            device.commands.append(f"no {line}")
            else:
                print(f"{device.hostname:39}[ERROR] show run inf {inf} - empty")


def make_config(device, settings):
    define_isis_interface(device)
    if settings["send-only"]:
        check_key_chain(device)
        phase1_send_only(device)
    elif settings["key-chain"]:
        phase2_authentication_mode(device)
    elif settings["no-send-only"]:
        phase3_authentication_mode(device)


def configure(device, settings):
    if settings["conf"]:
        if len(device.commands) > 0:
            device.configure(device.commands)
            device.commit()
            print(f"{device.hostname:39}commit")

    if len(device.commands) > 0:
        print(f"{device.hostname:39}cfg is needed")


#######################################################################################
# ------------------------------              ----------------------------------------#
#######################################################################################

def connect_dev(my_username, my_password, dev_queue, settings):
    while True:
        device = dev_queue.get()
        i = 0
        while True:
            try:
                device.ssh_conn = ConnectHandler(device_type=device.os_type, ip=device.ip_address,
                                                 username=my_username, password=my_password)
                make_config(device, settings)
                configure(device, settings)
                device.ssh_conn.disconnect()
                dev_queue.task_done()
                break

            except NetMikoTimeoutException as err_msg:
                device.connection_status = False
                device.connection_error_msg = str(err_msg)
                print(f"{device.hostname:23}{device.ip_address:16}timeout")
                dev_queue.task_done()
                break
                 
            except SSHException:
                i += 1
                device.reset()
                print(f"{device.hostname:23}{device.ip_address:16}SSHException occurred \t i={i}")
                time.sleep(5)

            except Exception as err_msg:
                if i == 2:  # tries
                    device.connection_status = False
                    device.connection_error_msg = str(err_msg)
                    print(f"{device.hostname:23}{device.ip_address:16}{'BREAK connection failed':20} i={i}")
                    dev_queue.task_done()
                    break
                else:
                    i += 1
                    device.reset()
                    print(f"{device.hostname:23}{device.ip_address:16}ERROR connection failed \t i={i}")
                    time.sleep(5)


#######################################################################################
# ------------------------------ test        -----------------------------------------#
#######################################################################################

def test_connect2(my_username, my_password, dev_queue, settings):
    device = dev_queue.get()
    device.ssh_conn = ConnectHandler(device_type=device.os_type, ip=device.ip_address,
                                     username=my_username, password=my_password)
    make_config(device, settings)
    configure(device, settings)
    device.ssh_conn.disconnect()
    dev_queue.task_done()


#######################################################################################
# ------------------------------ main part -------------------------------------------#
#######################################################################################

starttime = datetime.now()
current_date = starttime.strftime("%Y.%m.%d")
current_time = starttime.strftime("%H.%M.%S")

log_folder = Path(f"{Path.cwd()}/logs/{current_date}/")  # current dir / logs / date /
log_folder.mkdir(exist_ok=True)

q = queue.Queue()

argv_dict = get_argv(argv)
username, password = get_user_pw()
devices = get_devinfo("devices.yaml")

total_devices = len(devices)

print("-------------------------------------------------------------------------------------------------------")
print("hostname               ip address      comment")
print("---------------------- --------------- ----------------------------------------------------------------")

for i in range(argv_dict["maxth"]):
    thread = Thread(target=connect_dev, args=(username, password, q, argv_dict))
    # thread = Thread(target=test_connect2, args=(username, password, q, argv_dict))
    thread.setDaemon(True)
    thread.start()

for device in devices:
    q.put(device)

q.join()

print()
failed_connection_count = write_logs(devices, current_time, log_folder, argv_dict)
duration = datetime.now() - starttime

print("-------------------------------------------------------------------------------------------------------")
print(f"failed connection: {failed_connection_count}  total device number: {total_devices}")
print(f"elapsed time: {duration}")
print("-------------------------------------------------------------------------------------------------------")
