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

from awmenu import consts
from awmenu.common import modulehelper
import awmenu.common.urwidwrapper as widget
import time
import urwid
import urwid.raw_display
import urwid.web_display

blank = urwid.Divider()


class SaveAndQuit(object):
    def __init__(self, parent):
        self.name = consts.SAVE_QUIT_MENU_NAME
        self.visible = True
        self.parent = parent
        self.screen = None
        # UI text
        saveandcontinue_button = widget.Button(consts.SAVE_AND_CONTINUE,
                                               self.save_and_continue)
        saveandquit_button = widget.Button(consts.SAVE_AND_QUIT, self.save_and_quit)
        quitwithoutsaving_button = widget.Button(consts.QUIT_WITHOUT_SAVE,
                                                 self.quit_without_saving)
        self.header_content = [consts.SAVE_QUIT_MENU_HEADER, blank,
                               saveandcontinue_button, saveandquit_button,
                               quitwithoutsaving_button]

        self.fields = []
        self.defaults = dict()

    def save_and_continue(self, args):
        self.save()

    def save_and_quit(self, args):
        if self.save():
            self.parent.refreshScreen()
            time.sleep(1.5)
            self.parent.exit(None)

    def save(self):
        results, modulename = self.parent.global_save()
        if results:
            self.parent.footer.set_text(consts.SAVE_QUIT_FOOTER)
            return True
        else:
            return False

    def quit_without_saving(self, args):
        self.parent.exit(None)

    def refresh(self):
        pass

    def screenUI(self):
        return modulehelper.ModuleHelper.screenUI(self, self.header_content,
                                                  self.fields, self.defaults,
                                                  buttons_visible=False)
