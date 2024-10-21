#!/usr/bin/env python3
# Copyright (C) 2010 Michael Ligh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# [NOTES] -----------------------------------------------------------
# 1) Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
# 2) The only requirement is pefile, other modules just add extra info
# 3) There are various versions of python-magic and pyssdeep - we try to support both
# original : http://code.google.com/p/malwarecookbook/source/browse/trunk/3/8/pescanner.py
# --------------------------------------------------------------------
# Changes made by Glenn P. Edwards Jr.
#   http://hiddenillusion.blogspot.com
#       @hiddenillusion
# Date: 10-15-2012
#
# Updated for Python 3 by Corey Forman (digitalsleuth)
# Date: 20-October-2024

import hashlib
import time
from datetime import datetime as dt
import binascii
import string
import os, sys
import subprocess
import re
import collections
import ppdeep
import argparse
import pefile
import peutils
import magic
import yara
import capstone

__tool__ = "pe-scanner"
__version__ = "2.0.0"
__maintainer__ = "Corey Forman (digitalsleuth)"


def header(msg):
    return f"\n{msg}\n{('=' * 90)}"


def subTitle(msg):
    if msg == "":
        return f"{('-' * 90)}"
    return f"{msg}\n{('-' * 90)}"


# suspicious APIs to alert on
# updated version from: http://code.google.com/p/peframe/
alerts_api = [
    "accept",
    "AddCredentials",
    "bind",
    "CertDeleteCertificateFromStore",
    "CheckRemoteDebuggerPresent",
    "closesocket",
    "connect",
    "ConnectNamedPipe",
    "CopyFile",
    "CreateFile",
    "CreateProcess",
    "CreateToolhelp32Snapshot",
    "CreateFileMapping",
    "CreateRemoteThread",
    "CreateDirectory",
    "CreateService",
    "CreateThread",
    "CryptEncrypt",
    "DeleteFile",
    "DeviceIoControl",
    "DisconnectNamedPipe",
    "DNSQuery",
    "EnumProcesses",
    "ExitThread",
    "FindWindow",
    "FindResource",
    "FindFirstFile",
    "FindNextFile",
    "FltRegisterFilter",
    "FtpGetFile",
    "FtpOpenFile",
    "GetCommandLine",
    "GetThreadContext",
    "GetDriveType",
    "GetFileSize",
    "GetFileAttributes",
    "GetHostByAddr",
    "GetHostByName",
    "GetHostName",
    "GetModuleHandle",
    "GetProcAddress",
    "GetTempFileName",
    "GetTempPath",
    "GetTickCount",
    "GetUpdateRect",
    "GetUpdateRgn",
    "GetUserNameA",
    "GetUrlCacheEntryInfo",
    "GetComputerName",
    "GetVersionEx",
    "GetModuleFileName",
    "GetStartupInfo",
    "GetWindowThreadProcessId",
    "HttpSendRequest",
    "HttpQueryInfo",
    "IcmpSendEcho",
    "IsDebuggerPresent",
    "InternetCloseHandle",
    "InternetConnect",
    "InternetCrackUrl",
    "InternetQueryDataAvailable",
    "InternetGetConnectedState",
    "InternetOpen",
    "InternetQueryDataAvailable",
    "InternetQueryOption",
    "InternetReadFile",
    "InternetWriteFile",
    "LdrLoadDll",
    "LoadLibrary",
    "LoadLibraryA",
    "LockResource",
    "listen",
    "MapViewOfFile",
    "OutputDebugString",
    "OpenFileMapping",
    "OpenProcess",
    "Process32First",
    "Process32Next",
    "recv",
    "ReadProcessMemory",
    "RegCloseKey",
    "RegCreateKey",
    "RegDeleteKey",
    "RegDeleteValue",
    "RegEnumKey",
    "RegOpenKey",
    "send",
    "sendto",
    "SetKeyboardState",
    "SetWindowsHook",
    "ShellExecute",
    "Sleep",
    "socket",
    "StartService",
    "TerminateProcess",
    "UnhandledExceptionFilter",
    "URLDownload",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualAllocEx",
    "WinExec",
    "WriteProcessMemory",
    "WriteFile",
    "WSASend",
    "WSASocket",
    "WSAStartup",
    "ZwQueryInformation",
]

alerts_imp = ["ntoskrnl.exe", "hal.dll", "ndis.sys"]

# legit entry point sections
good_ep_sections = [".text", ".code", "CODE", "INIT", "PAGE"]

# path to clamscan (optional)
clamscan_path = "/usr/bin/clamscan"


def convert_char(char):
    if (
        char in string.ascii_letters
        or char in string.digits
        or char in string.punctuation
        or char in string.whitespace
    ):
        return char
    else:
        return f"{ord(char):x}"


def convert_to_printable(s):
    return "".join([convert_char(c) for c in s])


def get_filetype(data):
    """There are two versions of python-magic floating around, and annoyingly, the interface
    changed between versions, so we try one method and if it fails, then we try the other.
    NOTE: you may need to alter the magic_file for your system to point to the magic file.
    """
    if "magic" in sys.modules:
        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            return ms.buffer(data)
        except:
            try:
                if isinstance(data, bytearray):
                    data = bytes(data)
                return magic.from_buffer(data)
            except magic.MagicException:
                magic_custom = magic.Magic(magic_file="C:\windows\system32\magic")
                return magic_custom.from_buffer(data)
    return ""


def get_ssdeep(filename):
    """
    The ppdeep library is a complete "pure-python" (pp) library for ssdeep.
    Given this, and its ease of use, we prefer that first. Otherwise,
    see if ssdeep is already installed and use that. But since the install of
    pescanner requires ppdeep, there should be no reason for it not to exist.
    """
    try:
        import ppdeep

        return ppdeep.hash_from_file(filename)
    except:
        try:
            import ssdeep

            return ssdeep.hash_from_file(filename)
        except:
            pass
    return ""


class PEScanner:
    def __init__(self, files, yara_rules=None, peid_sigs=None):
        self.files = files

        # initialize YARA rules if provided
        if yara_rules and "yara" in sys.modules:
            self.rules = yara.compile(yara_rules)
        else:
            self.rules = None

        # initialize PEiD signatures if provided
        if peid_sigs:
            self.sigs = peutils.SignatureDatabase(peid_sigs)
        else:
            self.sigs = None

    def check_ep_section(self, pe):
        """Determine if a PE's entry point is suspicious"""
        name = ""
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pos = 0
        for sec in pe.sections:
            if (ep >= sec.VirtualAddress) and (
                ep < (sec.VirtualAddress + sec.Misc_VirtualSize)
            ):
                name = sec.Name.replace(b"\x00", b"")
                break
            else:
                pos += 1
        return (ep, name, pos)

    def check_verinfo(self, pe):
        """Determine the version info in a PE file"""
        ret = []

        if hasattr(pe, "VS_VERSIONINFO"):
            if hasattr(pe, "FileInfo"):
                for entry in pe.FileInfo:
                    if hasattr(entry, "StringTable"):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                if "OriginalFilename" in str_entry:
                                    ret.append(
                                        f"{convert_to_printable(str_entry[0])}: {convert_to_printable(str_entry[1])}"
                                    )
                                else:
                                    ret.append(
                                        f"{convert_to_printable(str_entry[0])}\t: {convert_to_printable(str_entry[1])}"
                                    )
                    elif hasattr(entry, "Var"):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, "entry"):
                                ret.append(
                                    f"{convert_to_printable(var_entry.entry.keys()[0])}\t: {var_entry.entry.values()[0]}"
                                )
        return "\n".join(ret)

    def check_tls(self, pe):
        callbacks = []
        if (
            hasattr(pe, "DIRECTORY_ENTRY_TLS")
            and pe.DIRECTORY_ENTRY_TLS
            and pe.DIRECTORY_ENTRY_TLS.struct
            and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        ):
            callback_array_rva = (
                pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
                - pe.OPTIONAL_HEADER.ImageBase
            )
            idx = 0
            while True:
                func = pe.get_dword_from_data(
                    pe.get_data(callback_array_rva + 4 * idx, 4), 0
                )
                if func == 0:
                    break
                callbacks.append(func)
                idx += 1
        return callbacks

    def check_rsrc(self, pe):
        ret = {}
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            i = 0
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = f"{resource_type.name}"
                else:
                    name = f"{pefile.RESOURCE_TYPE.get(resource_type.struct.Id)}"
                if name == None:
                    name = f"{resource_type.struct.Id}"
                if hasattr(resource_type, "directory"):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size,
                                )
                                filetype = get_filetype(data)
                                lang = pefile.LANG.get(
                                    resource_lang.data.lang, "*unknown*"
                                )
                                sublang = pefile.get_sublang_name_for_lang(
                                    resource_lang.data.lang, resource_lang.data.sublang
                                )
                                ret[i] = (
                                    name,
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size,
                                    filetype,
                                    lang,
                                    sublang,
                                )
                                i += 1
        return ret

    def get_lang(self, pe):
        resources = self.check_rsrc(pe)
        ret = []
        lang_holder = []
        for rsrc in resources.keys():
            (name, rva, size, rsrc_type, lang, sublang) = resources[rsrc]
            lang_holder.append(lang)
            lang_count = collections.Counter(lang_holder)
            lang_common = lang_count.most_common(1)
            for lang_likely, occur in lang_common:
                ret = lang_likely.split("_")[1]
        return ret

    def check_imports(self, pe):
        ret = []
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return ret
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for entry in alerts_imp:
                if re.search(lib.dll, entry.encode(), re.I):
                    ret.append(lib.dll)
            for imp in lib.imports:
                if (imp.name != None) and (imp.name != ""):
                    for alert in alerts_api:
                        if imp.name.startswith(alert.encode()):
                            ret.append(imp.name)
        return ret

    # this requires pefile v1.2.10-139 +
    def get_imphash(self, pe):
        return pe.get_imphash()

    def get_timestamp(self, pe):
        val = pe.FILE_HEADER.TimeDateStamp
        ts = hex(val)
        try:
            ts += f" [{dt.utcfromtimestamp(val).strftime('%Y-%m-%d %H:%M:%S')} UTC]"
            that_year = int(dt.utcfromtimestamp(val).strftime("%Y"))
            this_year = dt.now().year
            if that_year < 2000 or that_year > this_year:
                ts += " [SUSPICIOUS]"
        except:
            ts += " [SUSPICIOUS]"
        return ts

    def check_packers(self, pe):
        packers = []
        if self.sigs:
            matches = self.sigs.match(pe, ep_only=True)
            if matches != None:
                for match in matches:
                    packers.append(match)
        return packers

    def check_yara(self, data):
        ret = []
        if self.rules:
            yarahits = self.rules.match(data=data)
            if yarahits:
                for hit in yarahits:
                    ret.append(f"YARA: {hit.rule}")
                    for key, stringname, val in hit.strings:
                        makehex = False
                        for char in val:
                            if char not in string.printable:
                                makehex = True
                                break
                        if makehex == True:
                            ret.append(f"\t{hex(key)} => {binascii.hexlify(val)}")
                        else:
                            ret.append(f"\t {hex(key)} => {val}")
        return "\n".join(ret)

    def check_clam(self, file, clamscan_path):
        if os.path.isfile(clamscan_path):
            command = [f"{clamscan_path}", f"{file}"]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode != 0:
                return f"Clamav: {result.stdout}"
        return ""

    def collect(self, verbose=False, clamscan=None):
        count = 0

        for file in self.files:
            out = []

            try:
                FILE = open(file, "rb")
                data = FILE.read()
                FILE.close()
            except:
                continue

            if data == None or len(data) == 0:
                out.append(f"Cannot read {file} (maybe empty?)")
                out.append("")
                continue

            try:
                pe = pefile.PE(data=data, fast_load=True)
                pe.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                    ]
                )
            except:
                out.append(f"Cannot parse {file} (maybe not PE?)")
                out.append("")
                continue

            # source: https://code.google.com/p/pyew/
            def get_filearch(data):
                if pe.FILE_HEADER.Machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
                    processor = "intel"
                    archtype = 32
                    bits = "32 Bit binary"
                elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                    processor = "intel"
                    archtype = 64
                    bits = "64 Bit binary"
                return processor, archtype, bits

            out.append(f'{("#" * 90)}\n[{count}]\tFile: {file}\n{("#" * 90)}')
            out.append(header("Metadata"))
            out.append(f"Size\t\t: {len(data)} bytes")
            out.append(f"Type\t\t: {get_filetype(data)}")
            processor, archtype, bits = get_filearch(data)
            out.append(f"Architecture\t: {bits}")
            out.append(f"MD5\t\t: {hashlib.md5(data).hexdigest()}")
            out.append(f"SHA1\t\t: {hashlib.sha1(data).hexdigest()}")
            out.append(f"ssdeep\t\t: {get_ssdeep(file)}")
            out.append(f"imphash\t\t: {self.get_imphash(pe)}")
            out.append(f"Date\t\t: {self.get_timestamp(pe)}")
            out.append(f"Language\t: {self.get_lang(pe)}")

            crc_claimed = pe.OPTIONAL_HEADER.CheckSum
            crc_actual = pe.generate_checksum()
            out.append(
                f"CRC (Claimed)   : 0x{crc_claimed}\nCRC (Actual)    : 0x{crc_actual} {'[SUSPICIOUS]' if crc_actual != crc_claimed else ''}"
            )

            packers = self.check_packers(pe)
            if len(packers):
                out.append(f"Packers\t\t: {','.join(packers)}")

            # Alert if the EP section is not in a known good section or if its in the last PE section
            (ep, name, pos) = self.check_ep_section(pe)
            ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase
            s = f"Entry Point\t: {hex(ep_ava)} {name.decode()} {pos}/{len(pe.sections)}"
            if (name not in good_ep_sections) or pos == len(pe.sections):
                s += " [SUSPICIOUS]\n"
            else:
                s += "\n"
            out.append(s)

            # Dism. the first 100 bytes of the Entry Point
            # out.append('Disassembly of first 100 bytes\n')
            s = f"{header('Disassembly of first 100 bytes')}\n{subTitle('Offset          Instructions')}\n"
            data = pe.get_memory_mapped_image()[ep : ep + 100]
            offset = 0
            if archtype == 32:
                cs_arch = capstone.CS_ARCH_X86
                cs_mode = capstone.CS_MODE_32
            elif archtype == 64:
                cs_arch = capstone.CS_ARCH_X86
                cs_mode = capstone.CS_MODE_64
            md = capstone.Cs(cs_arch, cs_mode)
            for instruction in md.disasm(data, offset):
                s += f"0x{instruction.address:08x}\t{instruction.mnemonic:<8} {instruction.op_str:<12}\n"
            out.append(s)

            verinfo = self.check_verinfo(pe)
            if len(verinfo):
                out.append(header("Version info"))
                out.append(verinfo)

            if "yara" in sys.modules:
                yarahits = self.check_yara(data)
            else:
                yarahits = []

            clamhits = []
            if clamscan:
                clamhits = self.check_clam(file, clamscan)

            if len(yarahits) or len(clamhits):
                out.append(header("Signature scans"))
                if len(yarahits):
                    out.append(yarahits)
                if len(clamhits):
                    out.append(clamhits)

            callbacks = self.check_tls(pe)
            if len(callbacks):
                out.append(header("TLS callbacks"))
                for cb in callbacks:
                    out.append(f"    0x{cb}")

            out.append(header("Sections"))
            out.append(
                f"{'Name':<10} {'VirtAddr':<12} {'VirtSize':<12} {'RawSize':<10} {'MD5':<12} {'Entropy':>27}"
            )
            out.append(subTitle(""))

            for sec in pe.sections:
                s = f'{"".join([chr(c) for c in sec.Name if chr(c) in string.printable]):<10} {hex(sec.VirtualAddress):<12} {hex(sec.Misc_VirtualSize):<12} {hex(sec.SizeOfRawData):<10} {sec.get_hash_md5():<12} {sec.get_entropy():<12.7f}'
                if (
                    sec.SizeOfRawData == 0
                    or (sec.get_entropy() > 0 and sec.get_entropy() < 1)
                    or sec.get_entropy() > 7
                ):
                    s += "[SUSPICIOUS]"
                out.append(s)

            resources = self.check_rsrc(pe)
            if len(resources):
                out.append(header("Resource entries"))
                names_holder = []
                for rsrc in resources.keys():
                    (name, rva, size, rsrc_type, lang, sublang) = resources[rsrc]
                    names_holder.append(name)
                    names_count = collections.Counter(names_holder)
                    names_common = names_count.most_common()
                out.append(f"{'Resource type':<18} {'Total':<8}")
                out.append(subTitle(""))
                for name, occur in names_common:
                    out.append(f"{name:<18} {occur:<8}")
                if verbose:
                    out.append("-" * 90)
                    out.append(
                        f"{'Name':<18} {'RVA':<8} {'Size':<8} {'Lang':<12} {'Sublang':<24} Type"
                    )
                    out.append("-" * 90)
                    for rsrc in resources.keys():
                        (name, rva, size, rsrc_type, lang, sublang) = resources[rsrc]
                        out.append(
                            f"{name:<18} {hex(rva):<8} {hex(size):<8} {lang:<12} {sublang:<24} {rsrc_type}"
                        )

            # source: https://code.google.com/p/pyew/
            imports_total = len(pe.DIRECTORY_ENTRY_IMPORT)
            if imports_total > 0:
                c = 1
                out.append(header("Imports"))
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    out.append(f"[{c}]\t{(entry.dll).decode()}")
                    if verbose:
                        for imp in entry.imports:
                            if (imp.name != None) and (imp.name != ""):
                                out.append(
                                    f"\t{hex(imp.address)} {(imp.name).decode()}"
                                )
                    c += 1

            imports = self.check_imports(pe)
            if len(imports):
                ret = []
                out.append(header("Suspicious IAT alerts"))
                for imp in imports:
                    ret.append(imp)
                c = 1
                for i in sorted(set(ret)):
                    out.append(f"[{c}]\t{i.decode()}")
                    c += 1

            # Grab the exports info , if available
            if (
                hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
                and pe.DIRECTORY_ENTRY_EXPORT.symbols
            ):
                c = 1
                if verbose:
                    out.append(header("#\tOffset\t\tExport"))
                else:
                    out.append(header("Exports"))
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if verbose:
                        out.append(f"[{c}]\t0x{exp.address:08x}\t{exp.name.decode()}")
                    else:
                        out.append(f"[{c}]\t{exp.name.decode()}")
                        c += 1
            out.append("")
            print("\n".join(out))
            count += 1


def main():
    parser = argparse.ArgumentParser(
        prog=__tool__,
        description=f"%(prog)s v" f"{str(__version__)}",
        formatter_class=argparse.HelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--clamscan",
        metavar="<path-to-clamscan>",
        help="Path to clamscan, will scan if chosen",
        required=False,
        default=None,
    )
    parser.add_argument(
        "-f",
        "--file",
        metavar="<input-file>",
        help="File to scan",
        required=True,
    )
    parser.add_argument(
        "-u",
        "--userdb",
        metavar="<userdb-file>",
        help="Path to your userdb.txt",
        required=False,
        default=None,
    )
    parser.add_argument(
        "-y",
        "--yara",
        metavar="<yara-rule>",
        help="Path to your yara rules",
        required=False,
        default=None,
    )
    parser.add_argument(
        "--verbose",
        help="Verbose mode - print more detail to stdout",
        required=False,
        action="store_true",
    )
    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()
    files = []
    if os.path.isdir(args.file):
        for root, dirs, filenames in os.walk(args.file):
            for name in filenames:
                files.append(os.path.join(root, name))
    elif os.path.isfile(args.file):
        files.append(args.file)

    # You should fill these in with a path to your YARA rules and PEiD database
    pescan = PEScanner(files, args.yara, args.userdb)
    pescan.collect(args.verbose, args.clamscan)


if __name__ == "__main__":
    main()
