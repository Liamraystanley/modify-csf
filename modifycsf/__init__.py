from __future__ import print_function
import argparse
import sys
import re
import os
import itertools
import psutil
import subprocess
from shutil import copyfile

version = "0.0.1"
csf_binary_location = "/usr/sbin/csf"

parser = argparse.ArgumentParser(
    description="Port modification wrapper for ConfigServer Security&Firewall")
parser_ports = parser.add_mutually_exclusive_group()
parser_ports.add_argument("-a", "--allow",
                          help="port to add to CSF's allow list; specify range with n:n")
parser_ports.add_argument("-r", "--remove",
                          help="port to remove from CSF's allow list; specify range with n:n")
parser_ports.add_argument("-l", "--list", action="store_true",
                          help="list of ports, and their protocols (tcp, udp, ipv4, ipv6)")
parser_protocols = parser.add_mutually_exclusive_group()
parser_protocols.add_argument("-4", "--four", action="store_true",
                              help="add/remove from IPv4 only")
parser_protocols.add_argument("-6", "--six", action="store_true",
                              help="add/remove from IPv6 only")
bounds = parser.add_mutually_exclusive_group()
bounds.add_argument("-i", "--inbound", action="store_true",
                    help="specify inbound when adding/removing ports")
bounds.add_argument("-o", "--outbound", action="store_true",
                    help="specify outbound when adding/removing ports")
verbosity = parser.add_mutually_exclusive_group()
verbosity.add_argument("-q", "--quiet", action="store_true", help="disable output")
verbosity.add_argument("-v", "--verbose", action="store_true",
                       help="add extra output")
parser.add_argument("-p", "--protocol",
                    help="dependant on the options used, targets specific protocols (tcp, udp)")
parser.add_argument("--noheader", action="store_true",
                    help="don't print header when supplying a list")
parser.add_argument("--nobackup", action="store_true",
                    help="don't make a backup of the configuration file when making modifications")
parser.add_argument("-c", "--configfile", default="/etc/csf/csf.conf",
                    help="location to CSF configuration file")
parser.add_argument("--ignore-check", action="store_true",
                    help="don't check to see if CSF is installed in " + csf_binary_location)
parser.add_argument("-V", "--version", action="store_true", help="version information")


class mcsf(object):
    def __init__(self):
        self.vargs = parser.parse_args()
        self.config = {}

    def readconfig(self):
        self.out("Attempting to parse {}...".format(self.vargs.configfile), "extra")
        with open(self.vargs.configfile, "r") as f:
            raw = f.read()
        configlines = [[i.strip() for i in x] for x in re.findall(r'^([A-Za-z0-9_]+) = "(.*?)"$', raw, flags=re.MULTILINE)]
        _tmp = {}
        for line in configlines:
            _tmp[line[0]] = line[1]
        return _tmp

    def backup_config(self):
        self.out("Making a backup from {} to {}...".format(
            self.vargs.configfile, self.vargs.configfile + ".backup"), "extra")
        try:
            copyfile(self.vargs.configfile, self.vargs.configfile + ".backup")
            self.out("Successfully generated backup.", "extra")
        except Exception as e:
            self.out(
                "Unable to make a backup of the configuration file "
                "({}). Ignoring. ({})".format(self.vargs.configfile, str(e)), "extra")

    def update_config(self, value, keys):
        try:
            self.out("Attempting to write changes to {}...".format(
                     self.vargs.configfile), "extra")
            with open(self.vargs.configfile, "r") as f:
                tmp = f.read().split("\n")
                lines = []
                for line in tmp:
                    if line.startswith("#"):
                        lines.append(line)
                        continue
                    replaced = False
                    for key in keys:
                        if line.startswith(key + " "):
                            new = re.sub(r'^%s = ".*?"$' % key, '{} = "{}"'.format(key, value), line)
                            lines.append(new)
                            replaced = True
                            break
                    if not replaced:
                        lines.append(line)
            with open(self.vargs.configfile, "w") as f:
                f.write("\n".join(lines))
            self.out("Successfully saved configuration file.", "extra")
        except Exception as e:
            self.out("Unable to write changes to {} ({}). Exiting.".format(
                self.vargs.configfile, str(e)), "error")
            sys.exit(1)

    def column(self, data, headers=None):
        if headers and not self.vargs.noheader:
            data.insert(0, [re.sub(r".", "-", x) for x in headers])
            data.insert(0, headers)
        width = [max(map(len, col)) for col in zip(*data)]
        msg = "\n".join(["  ".join((val.ljust(width) for val, width in zip(row, width))) for row in data])
        return self.out(msg, severity="always")

    def out(self, msg, severity="normal"):
        severity = str(severity).lower()
        msg = str(msg).rstrip()
        if not severity == "always" and self.vargs.quiet:
            return
        if severity == "normal" or severity == "always":
            print(msg, file=sys.stdout)
        elif severity == "extra":
            if self.vargs.verbose:
                print(msg, file=sys.stdout)
        elif severity == "warning":
            print("[warning] {}".format(msg), file=sys.stderr)
        elif severity == "error":
            print("[error] {}" .format(msg), file=sys.stderr)
        else:
            print("[{}] {}".format(severity, msg), file=sys.stdout)
        return

    def run_checks(self):
        if self.vargs.version:
            self.out("Running mcsf version {}".format(version))
            sys.exit(0)

        # Check os. CSF should only be run on linux...
        if sys.platform != "linux" and sys.platform != "linux2":
            self.out("mcsf can only be used on Linux.", "error")
            sys.exit(1)

        # See if CSF is even installed..
        if not self.vargs.ignore_check and not os.path.isfile(csf_binary_location):
            self.out("It doesn't look like CSF is installed in {}. Exiting.".format(
                csf_binary_location), "error")
            sys.exit(1)

        # See if the config file exists/have perms
        if not os.path.isfile(self.vargs.configfile):
            self.out("The configuration file for CSF doesn't exist ({}) or can't read from it (are you running as root?). Exiting.".format(
                self.vargs.configfile), "error")
            sys.exit(1)

        # Run a couple of checks against arguments specified
        if self.vargs.allow:
            if not re.match(r"^[0-9]+(?:\:[0-9]+)?$", self.vargs.allow):
                self.out("Invalid protocol specified. (use udp or tcp). Ignoring.", "warning")
                self.vargs.protocol = False

        if self.vargs.remove:
            if not re.match(r"^[0-9]+(?:\:[0-9]+)?$", self.vargs.remove):
                self.out("Invalid protocol specified. (use udp or tcp). Ignoring.", "warning")
                self.vargs.protocol = False

        if self.vargs.remove or self.vargs.allow:
            if not self.vargs.inbound and not self.vargs.outbound:
                self.out(
                    "-i (inbound) or -o (outbound) must be specified when adding "
                    "or removing ports.", "error")
                sys.exit(1)

        if self.vargs.protocol:
            if not re.match(r"(?i)^(tcp|udp)$", self.vargs.protocol):
                self.out("Invalid protocol specified. (use udp or tcp).", "error")
                sys.exit(1)
        else:
            self.vargs.protocol = ""

        # Ensure they're at least passing us something to do...
        # Then try and read from it. If it fails, either the file
        # isn't the correct file, there is a syntax error, or possibly
        # something else...
        try:
            self.config = self.readconfig()
        except Exception as e:
            self.out("Error while parsing {}: {}".format(self.vargs.configfile, str(e)), "error")
            sys.exit(1)

        # Some pre-configuration of what matches, and what doesn't
        if self.vargs.allow or self.vargs.remove:
            config_range = []
            port_range = []
            if self.vargs.protocol.upper() == "TCP" or not self.vargs.protocol:
                if self.vargs.four or not self.vargs.four and not self.vargs.six:
                    if self.vargs.inbound:
                        config_range.append("TCP_IN")
                    if self.vargs.outbound:
                        config_range.append("TCP_OUT")
                if self.vargs.six or not self.vargs.four and not self.vargs.six:
                    if self.vargs.inbound:
                        config_range.append("TCP6_IN")
                    if self.vargs.outbound:
                        config_range.append("TCP6_OUT")
            if self.vargs.protocol.upper() == "UDP" or not self.vargs.protocol:
                if self.vargs.four or not self.vargs.four and not self.vargs.six:
                    if self.vargs.inbound:
                        config_range.append("UDP_IN")
                    if self.vargs.outbound:
                        config_range.append("UDP_OUT")
                if self.vargs.six or not self.vargs.four and not self.vargs.six:
                    if self.vargs.inbound:
                        config_range.append("UDP6_IN")
                    if self.vargs.outbound:
                        config_range.append("UDP6_OUT")
            for item in config_range:
                port_range = port_range + self.unique_ports(self.config[item], conf=True)

        # --list
        if self.vargs.list:
            output = []
            if self.vargs.protocol:
                if self.vargs.four:
                    output.append(
                        ["INBOUND", "IPv4", self.config[self.vargs.protocol.upper() + "_IN"]])
                    output.append(
                        ["OUTBOUND", "IPv4", self.config[self.vargs.protocol.upper() + "_OUT"]])
                elif self.vargs.six:
                    output.append(
                        ["INBOUND", "IPv6", self.config[self.vargs.protocol.upper() + "6_IN"]])
                    output.append(
                        ["OUTBOUND", "IPv6", self.config[self.vargs.protocol.upper() + "6_OUT"]])
            else:
                    output.append(["INBOUND", "TCP", "IPv4", self.config["TCP_IN"]])
                    output.append(["OUTBOUND", "TCP", "IPv4", self.config["TCP_OUT"]])
                    output.append(["INBOUND", "TCP", "IPv6", self.config["TCP6_IN"]])
                    output.append(["OUTBOUND", "TCP", "IPv6", self.config["TCP6_OUT"]])
                    output.append(["INBOUND", "UDP", "IPv4", self.config["UDP_IN"]])
                    output.append(["OUTBOUND", "UDP", "IPv4", self.config["UDP_OUT"]])
                    output.append(["INBOUND", "UDP", "IPv6", self.config["UDP6_IN"]])
                    output.append(["OUTBOUND", "UDP", "IPv6", self.config["UDP6_OUT"]])
            self.column(output, headers=["METHOD", "TYPE", "PROTOCOL", "PORTS"])

        # --allow
        elif self.vargs.allow:
            if ":" in self.vargs.allow:
                ports = range(
                    int(self.vargs.allow.split(":")[0]),
                    int(self.vargs.allow.split(":")[1]) + 1)
                ports = self.unique_ports(set(ports + port_range))
            else:
                ports = self.unique_ports(set([int(self.vargs.allow)] + port_range))
            self.backup_config()
            self.update_config(ports, keys=config_range)
            self.out("Added port(s) {}.".format(self.vargs.allow))
            self.restart_csf()

        # --remove
        elif self.vargs.remove:
            if ":" in self.vargs.remove:
                ports = range(
                    int(self.vargs.remove.split(":")[0]),
                    int(self.vargs.remove.split(":")[1]) + 1)
                ports = self.unique_ports([x for x in set(port_range) if x not in ports])
            else:
                ports = [int(self.vargs.remove)]
                ports = self.unique_ports([x for x in set(port_range) if x not in ports])
            self.backup_config()
            self.update_config(ports, keys=config_range)
            self.out("Removed port(s) {}.".format(self.vargs.remove))
            self.restart_csf()

        else:
            self.out(
                "Not enough arguments supplied. Please use 'mcsf --help' "
                "on how to use mcsf.", "error")
            sys.exit(1)

    def unique_ports(self, port_list, conf=False, ranges=True):
        if conf:
            tmp = []
            port_list = port_list.replace(" ", "").split(",")
            try:
                for port in port_list:
                    if ":" in port:
                        [tmp.append(int(x)) for x in range(int(port.split(":")[0]), int(port.split(":")[1]) + 1)]
                    else:
                        tmp.append(int(port))
            except:
                self.out("Invalid ports in the configuration file. Exiting.", "error")
                sys.exit(1)
            return tmp
        else:
            tmp = []
            port_list = list(port_list)
            port_list.sort(key=int)
            new = list(self.range_compress(port_list))
            for port_range in new:
                if port_range[0] == port_range[1]:
                    tmp.append(str(port_range[0]))
                else:
                    tmp.append(str(port_range[0]) + ":" + str(port_range[1]))
            return ",".join(tmp)

    def range_compress(self, i):
        for a, b in itertools.groupby(enumerate(i), lambda (x, y): y - x):
            b = list(b)
            yield b[0][1], b[-1][1]

    def restart_csf(self):
        self.out("Checking if LFD/CSF is running...", "extra")
        p = subprocess.Popen([csf_binary_location, '-r'], stdout=subprocess.PIPE)
        out = p.communicate()
        if "LOGDROPIN" in out[0]:
            # Assume it's running
            self.out("Found LFD process. CSF restarted", "extra")
            self.out("Successfully restarted CSF.")
        else:
            self.out("Error while attempting to restart CSF...", "extra")
            self.out("Please start CSF with 'csf -e'.")

    def run(self):
        try:
            self.run_checks()
        except Exception as e:
            self.out("Error while attempting to process: " + str(e), "error")
            sys.exit(1)

if __name__ == "__main__":
    main = mcsf().run()
