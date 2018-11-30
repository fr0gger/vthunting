# VT Hunting
                                                    
Virus Total Hunting is a tiny tool based on the VT api version 3 to run daily, weekly or monthly report about malware hunting. 
The report can be send via email, Slack channel or Telegram. The tool can also be used in cli to get a report anytime. 
The default number of result is 10 but it can be increase or decrease in the config part. 
This tool is only working with a Virus Total Intelligence API. 

#### Report Example

The below extract is an example of generated report.
```
    __     _______   _   _             _   _            
    \ \   / /_   _| | | | |_   _ _ __ | |_(_)_ __   __ _ 
     \ \ / /  | |   | |_| | | | | '_ \| __| | '_ \ / _` |
      \ V /   | |   |  _  | |_| | | | | |_| | | | | (_| |
       \_/    |_|   |_| |_|\__,_|_| |_|\__|_|_| |_|\__, |
                                                    |___/ 
        
            McAfee ATR | Thomas Roccia | @fr0gger_
        Get latest hunting notification from VirusTotal


Latest report from 2018-12-24 10:20:30.158831
-------------------------------------------------------------------------------------
Rule name: FancyBear_ComputraceAgent
Match date: 2018-12-24 17:38:17
SHA256: f5157e5b8afe1f79f29c947449477d13ede3d7341699256e62966474a7ee1eb5
Tags: [apt28, fancybear_computraceagent]
-------------------------------------------------------------------------------------
Rule name: Winexe_RemoteExecution
Match date: 2018-12-24 15:01:15
SHA256: 1e194647c05b0068c31cd443b5bcacc2dd41799e5d21a40e0c58adbad01c28c6
Tags: [winexe_remoteexecution, apt28]
-------------------------------------------------------------------------------------
Rule name: hatman_compiled_python: hatman
Match date: 2018-12-24 00:28:21
SHA256: 14c64fc93ae68f01989db992bf8ee47ffd33edf66223b84f3fae52f9a843a03f
Tags: [triton, hatman, hatman_compiled_python]
-------------------------------------------------------------------------------------
Rule name: Stuxnet_unpacked
Match date: 2018-12-24 15:00:00
SHA256: 86b05279bf4930ffc0c00e4fd22c8ab9e964e8d45d39bfca42e129b95dc33481
Tags: [stuxnet, stuxnet_unpacked]
-------------------------------------------------------------------------------------
Rule name: Stuxnet
Match date: 2018-12-24 14:59:59
SHA256: 86b05279bf4930ffc0c00e4fd22c8ab9e964e8d45d39bfca42e129b95dc33481
Tags: [stuxnet]
-------------------------------------------------------------------------------------
[truncated]
```

## Getting Started
Just download the script: 
```
git clone https://github.com/fr0gger/vthunting
```

Then configure the config part with your API keys and info:
```
# Virus Total API
VTAPI = "<API_KEY>"
number_of_result = "" # 10 by default

# Email configuration 
smtp_serv = "<SMTP_SERV>"
smtp_port = ""
gmail_login = "<EMAIL>"
gmail_pass = "<APP_PASS>"  # pass from APP
gmail_dest = "<DEST_EMAIL>"

# Slack Bot config
SLACK_BOT_TOKEN = "<API>"
SLACK_CHANNEL = "<SLACK_CHANNEL>"

# Telegram Bot config
TOKEN = "<API>"
chat_id = "<CHAT_ID>"
```

Once the config is ready you can run the file with:
```
python vthunting.py --help
```

### Prerequisites
##### Requirements
You first need to install the requirement:
* requests
* slackclient

```
pip install -r requirements.txt
```
##### VT API
Get your API key from Virus Total. https://developers.virustotal.com/v3.0/reference

##### Email Configuration (gmail)
To create an app you can find the documentation here: https://support.google.com/accounts/answer/185833

##### Slack Bot Configuration
To generate a token you need to go here and follow the step: https://api.slack.com/custom-integrations/legacy-tokens

##### Telegram Bot Configuration
To get a token you need to create a Telegram bot by talking to @BotFather, it will help you to configure your bot and 
get your token. 
Once you get your token visit https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates to get the channel id.

### Install in your system

If you want to access to this script anywhere you can copy it without the extension into: 


```
cp vthunting.py /usr/local/bin/vthunting
```

### Configure the task scheduler with crontab
You can use crontab to run the script and receive report periodically.

```
crontab -e 
```
Below is an example to receive the report every day at 10:15am. 

```
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  *  user command to be executed

15 10  * * * /usr/local/bin/vthunting -r -t -e -s >> vthunt.log
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details


