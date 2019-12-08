#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Virus Total Hunting Notification version 1.0
This tiny python script allows you to setup daily report about virustotal hunting notification.
You can send the report by email, to telegram or slack and export the result in JSON.

Usage:
python vthunting.py [options]

Install:
pip install requests slackclient
"""

import requests
import json
import datetime as dt
import re
import smtplib
import getopt
import sys
from requests import *
from datetime import datetime
from slackclient import SlackClient


# authorship information
__author__ = "Thomas Roccia | @fr0gger_"
__team__ = "ATR"
__version__ = "1.0"
__maintainer__ = "@fr0gger_"
__status__ = "Release 1.0"
__asciiart__ = '''
    __     _______   _   _             _   _
    \ \   / /_   _| | | | |_   _ _ __ | |_(_)_ __   __ _
     \ \ / /  | |   | |_| | | | | '_ \| __| | '_ \ / _` |
      \ V /   | |   |  _  | |_| | | | | |_| | | | | (_| |
       \_/    |_|   |_| |_|\__,_|_| |_|\__|_|_| |_|\__, |
                                                    |___/
        '''
# -----------------------------------------------------------------------
#                               CONFIG INFO
#                       UPDATE WITH YOUR PERSONAL INFO
# -----------------------------------------------------------------------
# Virus Total Intelligence API
VTAPI = ""
number_of_result = ""  # 10 by default
vturl = 'https://www.virustotal.com/api/v3/intelligence/hunting_notifications?cursor=&limit=' + number_of_result

# Create an APP on gmail if you are using double authentication https://support.google.com/accounts/answer/185833
smtp_serv = ""
smtp_port = ""
gmail_login = ""
gmail_pass = ""  # pass from APP
gmail_dest = ""

# Slack Bot config
SLACK_BOT_TOKEN = ""
SLACK_EMOJI = ":rooster:"
SLACK_BOT_NAME = "VT Hunting Bot by @fr0gger_"
SLACK_CHANNEL = ""

# Telegram Bot config
# to get the token just ping @Botfather on telegram and create a new bot /new_bot
# To get a chat id send a message to your bot and go to https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
TOKEN = ""
chat_id = ""
telurl = "https://api.telegram.org/bot{}/".format(TOKEN)
# -----------------------------------------------------------------------

# Global Variable
now = dt.datetime.now()
headers = {"x-apikey": VTAPI}
regex = "[A-Fa-f0-9]{64}"  # Detect SHA256
end_message = "From fr0gger with <3"


# Print help
def usage():
    print("usage: vthunting.py [OPTION]")
    print('''    -h, --help              Print this help
    -r, --report            Print the VT hunting report
    -s, --slack_report      Send the report to a Slack channel
    -e, --email_report      Send the report by email
    -t, --telegram_report   Send the report to Telegram
    -j, --json              Print report in json format
    ''')


# Posting to a Slack channel
def send_slack_report(report):
    sc = SlackClient(SLACK_BOT_TOKEN)
    if sc.rtm_connect(with_team_state=False):
        sc.api_call(
            "chat.postMessage",
            icon_emoji=SLACK_EMOJI,
            username=SLACK_BOT_NAME,
            channel=SLACK_CHANNEL,
            text=report
        )
        print("[*] Report have been sent to your Slack channel!")

    else:
        print("[!] Connection failed! Exception traceback printed above.")
        sys.exit()


# Posting to a Telegram channel
def send_telegram_report(report):
    url_gram = telurl + "sendMessage?text={}&chat_id={}".format(report, chat_id)
    response = requests.get(url_gram)
    if response:
        response.content.decode("utf8")
        print("[*] Report have been sent to Telegram!")

    else:
        print("[!] Connection to Telegram failed! Check your token or chat id.")


# Send email report
def send_email_report(report):
    from_email = gmail_login
    to_email = [gmail_dest]  # ['me@gmail.com', 'bill@gmail.com']
    subject = "Virus Total Hunting Report - " + str(now)
    text = report
    message = 'Subject: {}\n\n{}'.format(subject, text)

    try:
        server = smtplib.SMTP_SSL(smtp_serv, smtp_port)
        server.ehlo()
        server.login(from_email, gmail_pass)
        # Send the mail

        server.sendmail(from_email, to_email, message)
        server.quit()
        print("[*] Report have been sent to your email!")
    except smtplib.SMTPException as e:
        print("[!] SMTP error: " + str(e))
        sys.exit()


# Connect to VT
def api_request():
    response = requests.get(vturl, headers=headers)
    result = json.loads(response.text)

    # print result
    report = ["Latest report from " + str(now),
              "-------------------------------------------------------------------------------------"]

    for json_row in result['data']:
        subject = json_row["attributes"]["subject"]
        date = json_row["attributes"]["date"]
        tags = json_row["attributes"]["tags"]
        sha2 = re.search(regex, str(tags)).group()
        tags.remove(sha2)

        report.append("Rule name: " + subject)
        report.append("Match date: " + datetime.utcfromtimestamp(date).strftime('%d/%m/%Y %H:%M:%S'))
        report.append("SHA256: " + sha2)
        report.append("Tags: " + str([str(tags) for tags in tags]).replace("'", ""))

        report.append("-------------------------------------------------------------------------------------")

    report.append(end_message)
    report = ("\n".join(report))

    return report, result


def main():
    print(__asciiart__)
    print("\t         " + __team__ + " | " + __author__)
    print("\tGet latest hunting notification from VirusTotal\n")

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hrsetj",
                                   ["help", "report", "slack_report", "email_report", "telegram_report", "json"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    try:
        report, result_json = api_request()
    except(ConnectionError, ConnectTimeout, KeyError) as e:
        print("[!] Error with the VT API: " + str(e))
        sys.exit()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-r", "--report"):
            print report
        elif o in ("-s", "--slack_report"):
            send_slack_report(report)
        elif o in ("-e", "--email_report"):
            send_email_report(report)
        elif o in ("-t", "--telegram_report"):
            send_telegram_report(report)
        elif o in ("-j", "--json"):
            print json.dumps(result_json, sort_keys=True, indent=4)


if __name__ == '__main__':
    main()
