from urllib import parse as urlparse
import base64
from voodoo import Voodoo
voodoo_obj = Voodoo()

commands = {
    'whois': voodoo_obj.whois_table,
    'asn': voodoo_obj.asn_table,
    'cvesearch': voodoo_obj.cve_table,
    'greynoise': voodoo_obj.greynoise_table,
    'graynoise': voodoo_obj.greynoise_table,
    'haveibeenpwned': voodoo_obj.haveibeenpwned_table,
    'hibp': voodoo_obj.haveibeenpwned_table,
    'pdns': voodoo_obj.pdns_table,
    'shodan': voodoo_obj.shodan_table,
    'internetdb': voodoo_obj.internetdb_table,
    # 'screenshot'
    # 'tlsscan'
} 

def lambda_handler(event, context):
    # data comes b64 and also urlencoded name=value& pairs
    msg_map = dict(urlparse.parse_qsl(base64.b64decode(str(event['body'])).decode('ascii')))
    # will be /command name
    command = msg_map.get('command','err')
    # params ['asn','1.1.1.1']
    params = msg_map.get('text','err').strip().split(" ")
    subcommand = params[0].lower()
    if (len(params) < 2):
        response = f'available subcommands: {list(commands.keys())} + 1 parameter'
    elif (subcommand in commands.keys()):
        response = f'{commands[subcommand](params[1])}'
    else:
        response = f'illegal sub command >{subcommand}<, commands available {list(commands.keys())}'

    # logging
    # print(str(command) + ' ' + str(params) +' -> '+ response + ',original: '+ str(msg_map))

    return  {
        "response_type": "in_channel",
        "text": command + ' ' + " ".join(params),
        "attachments": [
            {
                "text": response
            }
        ]
    }

if __name__ == "__main__":
    test_dict = {
        "body": "Y29tbWFuZD0lMkZ2b29kb28mdGV4dD1hc24rMS4xLjEuMQo="
    }
    print(lambda_handler(test_dict,None))
    print("\n\n")
    test_dict = {
        "body": "Y29tbWFuZD0lMkZ2b29kb28mdGV4dD13aG9pcysxLjEuMS4xCg=="
    }
    print(lambda_handler(test_dict,None))