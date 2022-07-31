# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ipTracker
# Purpose:      Get information from ip
#
# Author:      https://github.com/Nf4ll
# Based on the template Daniel García Baamerio <dagaba12@gmail.com>
#
# Created:     30/07/2022
# Copyright:   (c) Pablo Partida Huetos 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import subprocess
import re


class sfp_ipTracker(SpiderFootPlugin):

    meta = {
        'name': "ipTracker",
        'summary': "Return information from ip. e.g: Location, enterprise, proxy.",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive DNS"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_RIR_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = None

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            #Conect to ip-api with fields in query parameters   
            ipData = subprocess.run(f'curl ip-api.com/json/{eventData}?fields=30605273', shell=True, text=True, capture_output=True) #
            
            #Get atributes from http request
            ipList = re.findall('"([^{]*)"' , str(ipData))

            castString = "".join(ipList)
            #Remove quotes
            rmQuotes = castString.replace('"', '')

            data = rmQuotes.replace(',', ', ')
                        
            if not data:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        evt = SpiderFootEvent("RAW_RIR_DATA", data, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_ipTracker class
