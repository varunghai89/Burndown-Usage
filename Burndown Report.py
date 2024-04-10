import mysql.connector
import logging
import os
import boto3
import json
from datetime import datetime
import requests

DEBUG = False
F_SENDEMAIL = True
ACCESS_KEY = "<enter aws access key>"
SECRET_KEY = "<enter aws secret key>"
ctmApiKey = "<enter ctm api key>"


data = {}
if(DEBUG):
    data['DEBUG'] = True
else:
    data['DEBUG'] = False

log = logging.getLogger()


toAddress = "asdf"
emailBody = "\n"
statusCode = 200
response = "FINISHED"
ctmToken = "None"
db = ""
cursor = ""
counter = 0

def dbConnect():
    global db,cursor
    log.info("Connecting to DB")
    db = mysql.connector.connect(
      host="<db host>",
      user="<dbuser>",
      password="<dbpassword>!",
      database="dbname"
    )
    cursor = db.cursor()
    log.debug("Successfully connected to DB")


def requestsDebugOutgoing():
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def runSql(sql):
    return doSql(sql, True)

def doSql(sql,fetch):
    log.debug("Executing Query: %s",sql)
    cursor.execute(sql)
    if(fetch):
        return cursor.fetchall()
    else:
        return True

def endSession():
    if(db.is_connected()):
        db.close()
        cursor.close()
        log.debug("Successfully disconnected from DB")

def addToEmail(text):
    global emailBody
    emailBody += text + "\n"

def calcColor(number):
    if number < 0:
        return("#FF0000")
    else:
        return("#000000")

def emailAddRow(name,current,previous):
    global counter
    counter += 1
    alert = False
    # Force ints for values that may be strs
    current = int(current)
    previous = int(previous)
    change = int(previous) - int(current)
    if change > 0 and (change % 24) == 0:
        alert = True

    change = change * -1

    if (counter % 2) == 0:
        bgColor = "#FFFFFF"
    else:
        bgColor = "BDDEFF"

    newRow = "<tr bgcolor='" + bgColor + "'>\n"
    if (alert == True):
        newRow += "<td><font color=red>" + name + "</font></td>\n"
    else:
        newRow += "<td>" + name + "</td>\n"

    color = calcColor(current)
    newRow += f"<td align=right><font color={color}>{current:,}</font></td>\n"
    # color = calcColor(previous)
    # newRow += f"<td align=right><font color={color}>{previous:,}</font></td>\n"
    if(change > 0):
        color = "#228B22"
    elif(change < 0):
        color = "#FF0000"
    else:
        color = "#"

    newRow += f"<td align=right><font color={color}>{change:,}</font></td>\n"
    newRow += "</tr>"

    addToEmail(newRow)

def sendEmail():
    global F_SENDEMAIL
    log.debug("Building Email")
    # fromAddress = toAddress
    fromAddress = "fromemail@from.com"
    from_email = fromAddress
    # config_set_name = os.environ['DefaultConfigSet']
    config_set_name = "DefaultConfigSet"
    client = boto3.client('ses', region_name='us-west-2')

    body_html = """<HTML><HEAD><BODY>
        <div style="font:normal 19px verdana, arial; color:#3d5bb1">Hosted Hour Usage Report</div><p>
        <table bgcolor=#4A8ACC cellpadding=5 cellspacing=0 style="border: 1px solid gray; font:normal 12px verdana, arial">
        <th><font color="white">Name</font></th><th><font color="white">Current Hours</font></th><!--<th><font color="white">Previous Hours</font></th>--><th><font color="white">Change</font></th>
    """ + emailBody + """
        </body>
        </html>
                    """
    log.debug("Email Body: \n" + body_html);

    t = datetime.now()
    today = t.strftime('%Y-%m-%d')

    email_message = {
        'Body': {
            'Html': {
                'Charset': 'utf-8',
                'Data': body_html,
            },
        },
        'Subject': {
            'Charset': 'utf-8',
            'Data': f"Hosted Hour Consumption: {today}",
        },
    }

    if(F_SENDEMAIL):
        log.info("Sending email")
        ses_response = client.send_email(
            Destination={
                'ToAddresses': [toAddress],
            },
            Message=email_message,
            Source=from_email,
            ConfigurationSetName=config_set_name,
        )

        # print(f"ses response id received: {ses_response['MessageId']}.")
        log.debug(f"ses response id received: {ses_response}.")
#end def sendEmail

def ctmAuthenticate():
    global statusCode,response
    putBody = {'apiToken': ctmApiKey, 'tenant':'customer licenses' }
    log.debug("Authenticating to CTM")
    r = requests.put('https://cloudtestmanager.soasta.com/concerto/services/rest/RepositoryService/v1/Tokens', data=json.dumps(putBody))
    if r.ok:
        ctmResponse = r.json()
        if "token" in ctmResponse:
            log.info("Authenticated to CTM with token: %s",ctmResponse['token'])
            return(ctmResponse['token'])
    else:
        log.error("Could not authenticate to CTM. CTM Response: %s",r)
        statusCode = 500
        response = "Could not authenticate to CTM: {r}"
        return("None")

def ctmGetLicense(key):
    query = {'key': key}
    header = {"X-Auth-Token":ctmToken}
    r = requests.get("https://cloudtestmanager.soasta.com/concerto/services/rest/RepositoryService/v1/Objects/license",params=query,headers=header)
    if r.ok:
        return r.json()

def getLicenseHours(licenseKey):
    hours = "Unknown"
    lic = ctmGetLicense(licenseKey)
    if len(lic.get('objects')) <= 0 or "attributes" not in lic.get('objects')[0]:
        log.error("Did not get license attributes from CTM for key: " + licenseKey)
        return("Unknown")

    attributes = lic['objects'][0]['attributes']
    for key in attributes:
        if key['name'] == "serverHours":
            hours = key['value']

    log.debug("Hours: %s",hours)

    if(hours == None):
        log.debug("Returning Unknown")
        return("Unknown")
    else:
        log.debug("Returning hours")
        return(hours)

    return(hours)


def lambda_handler(event, context):
    global ctmToken,statusCode,response,toAddress
    COMMIT = True
    # requestsDebugOutgoing()    # Enable debug logging of outgoing HTTP requests

    log.info("Event: " + json.dumps(event))

    if('DEBUG' in event and event['DEBUG']):
        log.info("DEBUG")
        log.setLevel(logging.DEBUG)
        logging.basicConfig(format='--> %(message)s',level=logging.DEBUG)
        toAddress = "toadress@to.com"
        COMMIT = False
    else:
        log.setLevel(logging.INFO)
        logging.basicConfig(format='--> %(message)s',level=logging.INFO)
        toAddress = "toadress@to.com"

    dbConnect()

    ctmToken = ctmAuthenticate()
    if ctmToken == "None":
        return {
            'statusCode': statusCode,
            'body': json.dumps(response)
        }

    log.debug("Query Database")
    query = runSql("SELECT * FROM Report WHERE enabled=1 ORDER BY name ASC")
    log.info("Getting server hours for (%i) license(s)...",len(query))

    for licenseRow in query:
        licenseKey = licenseRow[1]
        licenseName = licenseRow[0]
        prevHours = licenseRow[2]

        hours = getLicenseHours(licenseKey)
        if hours == "Unknown":
            log.error("Failed to get server hours from key: %s",licenseKey)

        else:
            log.info("Got (%i) Server Hours (Previous: %i) for License: %s",int(hours),int(prevHours),licenseName)

            log.debug("Writing Hours to DB")
            doSql(f"CALL UpdateServerHours('{licenseKey}',{hours})",False)

            emailAddRow(licenseName, hours, prevHours)
    if(COMMIT):
        doSql("COMMIT", False)
    else:
        log.debug("No Commit - running as DEBUG")

    sendEmail()

    return {
        'statusCode': statusCode,
        'body': json.dumps(response)
    }

if(DEBUG):
    lambda_handler(data, 1)
else:
    lambda_handler(data, 1)