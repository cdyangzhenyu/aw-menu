#!/usr/bin/env python
#-*- coding: utf-8 -*-
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

import netaddr

from awmenu import consts
from awmenu.common import errors as f_errors
from awmenu.common import modulehelper as helper
import awmenu.common.urwidwrapper as widget

import logging
import urwid

log = logging.getLogger('awmenu.awroles')


class AwRoles(urwid.WidgetWrap):
    def __init__(self, parent):
        self.name = consts.ROLE_MENU_NAME
        self.visible = True
        self.parent = parent
        self.saas_install = True
        # UI text
        role_keys = [consts.CLOUD_ROLE_NAME,
                     consts.NON_CLOUD_ROLE_NAME]
        self.role_choices = widget.ChoicesGroup(role_keys,
                                                default_value=self._select_default_role(role_keys),
                                                fn=self.radioSelect)
        # Placeholders for network settings text
        self.role_text1 = widget.TextLabel("")
        self.role_text2 = widget.TextLabel(consts.MGMT_IP_HEADER)
        self.header_content = [
            consts.ROLE_MENU_HEADER, "",
            self.role_choices, self.role_text1,
            self.role_text2]
        self.fields = ["mgmt_ip"]
        self.defaults = \
            {
                "mgmt_ip": {"label": consts.MGMT_IP_LABLE,
                           "tooltip": consts.MGMT_IP_TOOLTIP,
                           "value": self.parent.settings.get('saas_address', '')},
            }
        self.screen = None
    
    def _select_default_role(self, role_keys):
        return role_keys[0] if self.parent.settings.get('saas_install', True) \
                            else role_keys[1]

    def radioSelect(self, current, state, user_data=None):
        """Update cloud roles details and display information."""
        for rb in current.group:
            if rb.get_label() == current.get_label():
                continue
            if rb.base_widget.state is True:
                self.saas_install = (rb.base_widget.get_label() == u"云管")
                break

    def check(self, args):
        """Validate that all fields have valid values and sanity checks."""
        self.parent.footer.set_text(consts.CHECK_TIPS)
        self.parent.refreshScreen()
        # Get field information
        responses = dict()

        for index, fieldname in enumerate(self.fields):
            if fieldname != "blank":
                responses[fieldname] = self.edits[index].get_edit_text()

        # Validate each field
        errors = []
        
        if responses["mgmt_ip"]:
            try:
                if netaddr.valid_ipv4(responses["mgmt_ip"]):
                    if not netaddr.IPAddress(responses["mgmt_ip"]):
                        raise f_errors.BadIPException("Not a valid IP address")
                else:
                    raise f_errors.BadIPException("Not a valid IP address")
            except (f_errors.BadIPException, Exception):
                errors.append(consts.MGMT_IP_FORMAT_ERROR)
        else:
            errors.append(consts.MGMT_IP_BLANK_ERROR)

        if len(errors) > 0:
            self.parent.footer.set_text(consts.ERROR_TIPS)
            log.error("Errors: %s %s" % (len(errors), errors))
            helper.ModuleHelper.display_failed_check_dialog(self, errors)
            return False
        return responses

    def apply(self, args):
        responses = self.check(args)
        if responses is False:
            log.error("Check failed. Not applying")
            return False
        self.parent.footer.set_text(consts.APPLY_SUCCESS_TIPS)
        self.save(responses)
        return True

    def save(self, responses):
        newsettings = helper.ModuleHelper.make_settings_from_responses(responses)
        newsettings['code'] = 'fffff'
        newsettings['saas_address'] = responses['mgmt_ip']
        newsettings['url'] = 'http://%s:9080' % responses['mgmt_ip']
        newsettings['saas_install'] = self.saas_install
        self.parent.settings.merge(newsettings)

    def cancel(self, button):
        helper.ModuleHelper.cancel(self, button)

    def refresh(self):
        pass

    def screenUI(self):
        return helper.ModuleHelper.screenUI(self, self.header_content,
                                            self.fields, self.defaults)
