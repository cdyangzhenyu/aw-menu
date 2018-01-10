#!/usr/bin/env python
# Copyright 2018 Awcloud, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import netaddr
import re
import socket
import urwid
import collections

from awmenu import consts
from awmenu.common import errors as f_errors
from awmenu.common import modulehelper
from awmenu.common import network
from awmenu.common import replace
from awmenu.common import utils
import awmenu.common.urwidwrapper as widget

blank = urwid.Divider()


# Need to define fields in order so it will render correctly


class Interfaces(urwid.WidgetWrap):
    def __init__(self, parent):
        self.name = consts.NETWORK_MENU_NAME
        self.visible = True
        self.netsettings = dict()
        self.parent = parent
        self.screen = None
        self.log = logging
        self.log.basicConfig(filename='./awmenu.log', level=logging.DEBUG)
        self.getNetwork()
        self.gateway = self.get_default_gateway_linux()
        self.activeiface = self._select_default_interface(sorted(self.netsettings.keys()))
        self.extdhcp = True

        # UI text
        self.net_choices = widget.ChoicesGroup(sorted(self.netsettings.keys()),
                                               default_value=self.activeiface,
                                               fn=self.radioSelectIface)
        # Placeholders for network settings text
        self.net_text1 = widget.TextLabel("")
        self.net_text2 = widget.TextLabel("")
        self.net_text3 = widget.TextLabel("")
        self.header_content = [consts.NETWORK_MENU_HEADER, "",
                               self.net_choices, "", self.net_text1,
                               self.net_text2, self.net_text3]
        self.fields = ["blank", "ifname", "blank", "ipaddr",
                       "netmask", "gateway", "dns"]
        self.defaults = \
            {
                "ifname": {"label": consts.NETWORK_INTERFACE_NAME_LABLE,
                           "tooltip": consts.NETWORK_INTERFACE_NAME_TOOLTIP,
                           "value": "locked"},
                "ipaddr": {"label": consts.NETWORK_IPADDR_LABLE,
                           "tooltip": consts.NETWORK_IPADDR_TOOLTIP,
                           "value": ""},
                "netmask": {"label": consts.NETWORK_NETMASK_LABLE,
                            "tooltip": consts.NETWORK_NETMASK_TOOLTIP,
                            "value": "255.255.255.0"},
                "gateway": {"label": consts.NETWORK_GATEWAY_LABLE,
                            "tooltip": consts.NETWORK_GATEWAY_TOOLTIP,
                            "value": ""},
                "dns": {"label": consts.NETWORK_DNS_LABLE,
                            "tooltip": consts.NETWORK_DNS_TOOLTIP,
                            "value": "114.114.114.114"},
            }

    def _select_default_interface(self, interfaces):
        for interface in interfaces:    
            if interface == self.parent.settings.get('interface_device', ''):
                return interface
        return interfaces[0]

    def fixEtcHosts(self):
        # replace ip for env variable HOSTNAME in /etc/hosts
        if self.netsettings[self.parent.managediface]["addr"] != "":
            managediface_ip = self.netsettings[self.parent.managediface][
                "addr"]
        else:
            managediface_ip = "127.0.0.1"
        found = False
        with open("/etc/hosts") as fh:
            for line in fh:
                if re.match("%s.*%s" % (managediface_ip, socket.gethostname()),
                            line):
                    found = True
                    break
        if not found:
            expr = ".*%s.*" % socket.gethostname()
            replace.replaceInFile("/etc/hosts", expr, "%s   %s %s" % (
                                  managediface_ip, socket.gethostname(),
                                  socket.gethostname().split(".")[0]))

    def check(self, args):
        """Validate that all fields have valid values and sanity checks."""
        # Get field information
        responses = dict()
        self.parent.footer.set_text("Checking data...")
        for index, fieldname in enumerate(self.fields):
            if fieldname == "blank" or fieldname == "ifname":
                pass
            else:
                responses[fieldname] = self.edits[index].get_edit_text()

        responses["bootproto"] = "none"
        responses["onboot"] = "yes"
        # Validate each field
        errors = []

        # Check for the duplicate IP provided
        for k, v in self.netsettings.items():
            if (k != self.activeiface and responses["ipaddr"] != ''
                    and responses["ipaddr"] == v.get('addr')):
                errors.append("The same IP address {0} is assigned for "
                              "interfaces '{1}' and '{2}'.".format(
                                  responses["ipaddr"], k, self.activeiface))
                break

        if responses["onboot"] == "no":
            numactiveifaces = 0
            for iface in self.netsettings:
                if self.netsettings[iface]['addr'] != "":
                    numactiveifaces += 1
            if numactiveifaces < 2 and \
                    self.netsettings[self.activeiface]['addr'] != "":
                # Block user because puppet l23network fails if all interfaces
                # are disabled.
                errors.append("Cannot disable all interfaces.")

        # Check ipaddr, netmask, gateway only if static
        elif responses["bootproto"] == "none":
            try:
                if netaddr.valid_ipv4(responses["ipaddr"]):
                    if not netaddr.IPAddress(responses["ipaddr"]):
                        raise f_errors.BadIPException("Not a valid IP address")
                else:
                    raise f_errors.BadIPException("Not a valid IP address")
            except (f_errors.BadIPException, Exception):
                errors.append(consts.MGMT_IP_FORMAT_ERROR)
            try:
                if netaddr.valid_ipv4(responses["netmask"]):
                    netmask = netaddr.IPAddress(responses["netmask"])
                    if netmask.is_netmask is False:
                        raise f_errors.BadIPException("Not a valid IP address")
                else:
                    raise f_errors.BadIPException("Not a valid IP address")
            except (f_errors.BadIPException, Exception):
                errors.append(consts.NETMASK_FORMAT_ERROR)
            try:
                if len(responses["gateway"]) > 0:
                    # Check if gateway is valid
                    if netaddr.valid_ipv4(responses["gateway"]) is False:
                        raise f_errors.BadIPException(
                            "Gateway IP address is not valid")
                    # Check if gateway is in same subnet
                    if network.inSameSubnet(responses["ipaddr"],
                                            responses["gateway"],
                                            responses["netmask"]) is False:
                        raise f_errors.BadIPException(
                            "Gateway IP is not in same "
                            "subnet as IP address")
            except (f_errors.BadIPException, Exception) as e:
                errors.append(consts.GATEWAY_SUBNET_ERROR)
            self.parent.footer.set_text("Scanning for duplicate IP address..")
            if len(responses["ipaddr"]) > 0:
                if self.netsettings[self.activeiface]['link'].upper() != "UP":
                    try:
                        network.upIface(self.activeiface)
                    except f_errors.NetworkException as e:
                        errors.append(consts.DUPLICATE_IP_ERROR)

                # Bind arping to requested IP if it's already assigned
                assigned_ips = [v.get('addr') for v in
                                self.netsettings.itervalues()]
                arping_bind = responses["ipaddr"] in assigned_ips

                if network.duplicateIPExists(responses["ipaddr"],
                                             self.activeiface, arping_bind):
                    errors.append(consts.DUPLICATE_HOST_ERROR.format(
                        responses["ipaddr"]))
        if len(errors) > 0:
            self.log.error("Errors: %s %s" % (len(errors), errors))
            modulehelper.ModuleHelper.display_failed_check_dialog(self, errors)
            return False
        else:
            self.parent.footer.set_text(consts.NO_ERROR_TIPS)
            return responses

    def apply(self, args):
        responses = self.check(args)
        if responses is False:
            self.log.error("Check failed. Not applying")
            self.parent.footer.set_text(consts.ERROR_TIPS)
            self.log.error("%s" % (responses))
            return False

        self.parent.footer.set_text(consts.AWCLOUD_CHANGING_FOOTER)

        # If there is a gateway configured in /etc/sysconfig/network, unset it
        expr = '^GATEWAY=.*'
        replace.replaceInFile("/etc/sysconfig/network", expr, "")

        try:
            self.parent.refreshScreen()
            self.setNetwork(args)
            modulehelper.ModuleHelper.getNetwork(self)
            gateway = self.get_default_gateway_linux()
            if gateway is None:
                gateway = ""
            self.fixEtcHosts()

        except Exception as e:
            self.log.error(e)
            self.parent.footer.set_text("Error applying changes. Check logs "
                                        "for details.")
            modulehelper.ModuleHelper.getNetwork(self)
            self.setNetworkDetails()
            return False

        self.parent.footer.set_text(consts.AWCLOUD_SUCCESS_FOOTER)
        modulehelper.ModuleHelper.getNetwork(self)
        self.setNetworkDetails()
        self.save(responses)
        return True

    def save(self, responses):
        newsettings = modulehelper.ModuleHelper.make_settings_from_responses(responses)
        newsettings['netaddr'] = responses['ipaddr']
        newsettings['netmask'] = responses['netmask']
        newsettings['dns'] = responses['dns']
        newsettings['interface_device'] = self.activeiface
        newsettings['gateway'] = responses['gateway']
        self.parent.settings.merge(newsettings)
    
    def setNetwork(self, args):
        responses = self.check(args)
        if responses is False:
            self.log.error("Check failed. Not applying")
            self.parent.footer.set_text("Check failed. Not applying.")
            self.log.error("%s" % (responses))
            return False

        netmask = responses["netmask"]
        ipaddr = responses["ipaddr"]
        #netmask_bits = netaddr.IPAddress(netmask).netmask_bits()
        #cidr = "%s/%s" % (responses["ipaddr"], netmask_bits)
        gateway = responses["gateway"]
        dns = responses["dns"]
        set_iface_up = ["ip", "link", "set", self.activeiface, "up"]
        utils.execute(set_iface_up)
        #set_Ip_command = ["ip", "addr", "add", cidr,
        #                  "dev", self.activeiface]
        set_Ip_command = ["ifconfig", self.activeiface, ipaddr,
                          "netmask", netmask]
        self.log.debug("Ip set cmd: %s" % (set_Ip_command))
        # Set network file
        network_file = "/etc/sysconfig/network-scripts/ifcfg-%s" % self.activeiface
        dns_file = "/etc/resolv.conf"
        network_dict = [
            ('DEVICE', self.activeiface),
            ('BOOTPROTO', 'static'),
            ('ONBOOT', 'yes'),
            ('TYPE', 'Ethernet'),
            ('USERCTL', 'yes'),
            ('PEERDNS', 'yes'),
            ('IPV6INIT', 'no'),
            ('IPADDR', ipaddr),
            ('NETMASK', netmask),
            ('DNS1', dns)]
        network_od = collections.OrderedDict(network_dict)
        if gateway:
            set_gateway = ["route", "add", "default", "gw",
                           gateway, self.activeiface]
            utils.execute(set_gateway)
            network_od['GATEWAY'] = gateway
        network_str = ''
        self.log.debug("network_od config: %s" % (network_od))
        for k in network_od.keys():
            network_str += '%s=%s\n' % (k, network_od[k])
        
        self.log.debug("Network config: %s" % (network_str))
        with open(network_file, 'w') as fh:
            fh.write(network_str)
        with open(dns_file, 'w') as fh:
            fh.write("nameserver %s" % dns) 
        utils.execute(set_Ip_command)

    def getNetwork(self):
        modulehelper.ModuleHelper.getNetwork(self)

    def getDHCP(self, iface):
        return modulehelper.ModuleHelper.getDHCP(iface)

    def get_default_gateway_linux(self):
        return modulehelper.ModuleHelper.get_default_gateway_linux()

    def radioSelectIface(self, current, state, user_data=None):
        """Update network details and display information."""
        # This makes no sense, but urwid returns the previous object.
        # The previous object has True state, which is wrong.
        # Somewhere in current.group a RadioButton is set to True.
        # Our quest is to find it.
        for rb in current.group:
            if rb.get_label() == current.get_label():
                continue
            if rb.base_widget.state is True:
                self.activeiface = rb.base_widget.get_label()
                break
        modulehelper.ModuleHelper.getNetwork(self)
        self.setNetworkDetails()

    def setNetworkDetails(self):
        self.net_text1.set_text("Interface: %-13s  Link: %s" % (
            self.activeiface,
            self.netsettings[self.activeiface]['link'].upper()))

        self.net_text2.set_text("IP:      %-15s  MAC: %s" % (
            self.netsettings[self.activeiface]['addr'],
            self.netsettings[self.activeiface]['mac']))
        self.net_text3.set_text("Netmask: %-15s  Gateway: %s" % (
            self.netsettings[self.activeiface]['netmask'],
            self.gateway))
        # Set text fields to current netsettings
        for index, fieldname in enumerate(self.fields):
            if fieldname == "ifname":
                self.edits[index].base_widget.set_edit_text(self.activeiface)
            elif fieldname == "ipaddr":
                self.edits[index].set_edit_text(self.netsettings[
                    self.activeiface]['addr'])
            elif fieldname == "netmask":
                self.edits[index].set_edit_text(self.netsettings[
                    self.activeiface]['netmask'])
            elif fieldname == "gateway":
                # Gateway is for this iface only if gateway is matches subnet
                if network.inSameSubnet(
                        self.netsettings[self.activeiface]['addr'],
                        self.gateway,
                        self.netsettings[self.activeiface]['netmask']):
                    self.edits[index].set_edit_text(self.gateway)
                else:
                    self.edits[index].set_edit_text("")

    def refresh(self):
        modulehelper.ModuleHelper.getNetwork(self)
        self.setNetworkDetails()

    def cancel(self, button):
        modulehelper.ModuleHelper.cancel(self, button)
        self.setNetworkDetails()

    def screenUI(self):
        return modulehelper.ModuleHelper.screenUI(self, self.header_content,
                                                  self.fields,
                                                  self.defaults,
                                                  show_all_buttons=True)
